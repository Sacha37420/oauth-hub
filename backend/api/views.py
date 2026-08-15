"""Vues.

Trois publics, trois familles d'endpoints — la lecture du fichier suit cet
ordre :

  1. Devs        CRUD sur les sites OAuth (`/api/providers/`).
  2. Utilisateur relier / délier ses propres comptes (`/api/connections/`,
                 `/api/providers/<slug>/authorize/`, `/api/callback/<slug>/`).
  3. Apps tierces obtenir le jeton amont de l'utilisateur courant
                 (`/api/providers/<slug>/token/`) — c'est LE endpoint pour
                 lequel cette app existe.
"""
import logging
from urllib.parse import urlparse, urlencode

from django.conf import settings
from django.db import transaction
from django.shortcuts import redirect
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import oauth
from .models import Connection, PendingAuthorization, Provider, TrustedClient
from .permissions import IsVaultAdminOrReadOnly, WritableFromHubOnly
from .serializers import (
    ConnectionSerializer, ProviderSerializer, TrustedClientSerializer,
)

logger = logging.getLogger(__name__)


# ── Helpers partagés ──────────────────────────────────────────────────────────

def _callback_uri(slug: str) -> str:
    """L'URI de rappel telle qu'elle doit être enregistrée côté site.

    Construite depuis la configuration (DOMAIN via OAUTH_HUB_BACKEND_PUBLIC_URL)
    et jamais codée en dur : c'est la même valeur qui est envoyée au site à
    l'aller, rejouée à l'échange, et affichée aux devs dans l'interface. Trois
    endroits, une seule source.
    """
    base = settings.OAUTH_HUB_BACKEND_PUBLIC_URL.rstrip('/')
    return f'{base}/api/callback/{slug}/'


def _api_url(slug: str, suffix: str) -> str:
    base = settings.OAUTH_HUB_BACKEND_PUBLIC_URL.rstrip('/')
    return f'{base}/api/providers/{slug}/{suffix}/'


def _return_params(provider: Provider, connection: 'Connection') -> dict:
    """Ce qu'on joint au retour sur l'URL de l'application cliente.

    Objectif : qu'une application de bureau reparte du callback avec **tout ce
    qu'il lui faut pour la suite**, sans avoir à coder en dur nos URLs ni à
    faire un aller-retour supplémentaire pour savoir où renouveler.

    ⚠ **Jamais le jeton ici, ni rien de secret.** Cette URL est ouverte dans le
    navigateur de l'utilisateur : elle atterrit dans l'historique, peut fuiter
    par l'en-tête `Referer`, et se retrouve dans les journaux de tout serveur
    local qui l'a vue passer. Le jeton se récupère sur `token_url`, par un appel
    authentifié — c'est-à-dire sur un canal que l'application contrôle.
    """
    params = {
        'connected': provider.pk,
        'provider': provider.pk,
        # Où redemander le jeton — c'est LA valeur qui évite de coder en dur
        # notre domaine et notre préfixe Caddy dans chaque application cliente.
        'token_url': _api_url(provider.pk, 'token'),
        # Où vérifier l'état sans faire transiter le jeton (affichage).
        'status_url': _api_url(provider.pk, 'status'),
        # Issuer Keycloak : permet à l'app de renouveler SON jeton (celui du
        # lab) sans le tenir d'ailleurs. Le renouvellement du jeton amont, lui,
        # est fait par oauth-hub et ne demande rien à l'application.
        'issuer': settings.KEYCLOAK_ISSUER_URI,
        # true ⇒ oauth-hub détient un refresh_token pour ce site et renouvellera
        # tout seul. false ⇒ le jeton est durable (cas d'une OAuth App GitHub)
        # OU il faudra repasser par une autorisation à l'expiration.
        'auto_renew': 'true' if connection.refresh_token_encrypted else 'false',
        'scope': connection.scope or '',
    }
    if connection.expires_at:
        params['expires_at'] = connection.expires_at.isoformat()
    if connection.account_label:
        params['account'] = connection.account_label
    return params


def _connect_url(slug: str, return_url: str = '') -> str:
    """Page de l'interface où l'utilisateur peut relier ce site.

    Renvoyée aux apps tierces en 409 : une app qui reçoit « pas de connexion »
    doit pouvoir envoyer son utilisateur au bon endroit sans connaître notre
    routage.
    """
    base = settings.OAUTH_HUB_FRONTEND_PUBLIC_URL.rstrip('/')
    params = {'connect': slug}
    if return_url:
        params['return_url'] = return_url
    return f'{base}/providers?{urlencode(params)}'


def _is_safe_return_url(url: str) -> bool:
    """Anti-open-redirect sur le paramètre `return_url`.

    Un endpoint de callback qui redirige vers une URL arbitraire fournie par
    l'appelant est un tremplin de hameçonnage classique : l'utilisateur voit un
    lien vers le domaine du lab, s'authentifie, et atterrit ailleurs. On
    n'autorise donc que deux familles :

      • le domaine public du lab lui-même (toutes les apps y vivent, seul le
        chemin change) ;
      • une **boucle locale** (127.0.0.1 / [::1] / localhost), indispensable
        pour les applications de bureau comme `storage_analysis`, qui écoutent
        sur un port local le temps de l'aller-retour.

    Tout le reste est refusé, y compris un sous-domaine du lab : `handle_path`
    de Caddy ne sert que le domaine nu, un sous-domaine serait donc soit
    inexistant, soit hors de notre contrôle.
    """
    if not url:
        return True  # absent ⇒ on retombera sur l'interface d'oauth-hub
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    host = (parsed.hostname or '').lower()
    if host in ('127.0.0.1', '::1', 'localhost'):
        return True
    allowed = {
        h.strip().lower()
        for h in settings.OAUTH_HUB_ALLOWED_RETURN_HOSTS.split(',')
        if h.strip()
    }
    return host in allowed


def _get_provider(slug: str, *, require_configured: bool = False) -> Provider:
    try:
        provider = Provider.objects.get(pk=slug)
    except Provider.DoesNotExist:
        raise NotFound(f"Aucun site OAuth enregistré sous le nom '{slug}'.")
    if require_configured and not provider.is_configured:
        raise ValidationError(
            f"Le site '{slug}' est incomplet ou désactivé : un développeur doit "
            "déposer son client_id et son client_secret dans oauth-hub avant "
            "toute connexion."
        )
    return provider


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Identité
# ══════════════════════════════════════════════════════════════════════════════

class MeView(APIView):
    """GET /api/me/ — qui je suis, et ai-je le droit d'administrer le coffre."""

    def get(self, request):
        return Response({
            'email': request.user.email,
            'username': request.user.username,
            'groups': request.user.groups,
            'is_vault_admin': request.user.is_vault_admin,
            # Utile au débogage d'une app tierce : elle voit sous quel client
            # Keycloak son jeton a été émis, donc pourquoi elle est acceptée.
            'client_id': request.user.client_id,
        })


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Devs : le coffre d'identifiants
# ══════════════════════════════════════════════════════════════════════════════

class ProviderViewSet(viewsets.ModelViewSet):
    """CRUD sur les sites OAuth. Lecture : tout le lab. Écriture : les devs.

    `slug` sert de clé primaire et d'identifiant d'URL — c'est lui qu'utilisent
    les apps tierces (`/api/providers/github/token/`), donc le renommer casse
    leurs appels. La création accepte de le choisir, la modification non.
    """

    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    # IsAuthenticated d'abord : IsVaultAdminOrReadOnly laisse passer toute
    # méthode sûre sans regarder l'identité, elle ne suffit donc jamais seule.
    permission_classes = [IsAuthenticated, IsVaultAdminOrReadOnly]
    lookup_field = 'slug'

    def get_serializer_context(self):
        return {**super().get_serializer_context(), 'request': self.request}

    def list(self, request, *args, **kwargs):
        """Liste enrichie de l'URI de rappel à enregistrer côté site.

        C'est l'information que les devs viennent chercher en premier et qu'ils
        ne peuvent pas deviner ; la calculer ici évite qu'elle soit recopiée à
        la main (donc fausse) dans la documentation.
        """
        response = super().list(request, *args, **kwargs)
        for item in response.data:
            item['callback_uri'] = _callback_uri(item['slug'])
        return response

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        response.data['callback_uri'] = _callback_uri(response.data['slug'])
        return response

    def perform_destroy(self, instance):
        # Les Connection tombent en cascade : supprimer un site révoque de fait
        # toutes les connexions du lab vers lui. C'est le comportement voulu
        # (le jeton n'aurait plus de client_secret pour être rafraîchi), mais il
        # mérite une trace.
        count = instance.connections.count()
        logger.warning(
            "Suppression du site '%s' par %s — %d connexion(s) supprimée(s).",
            instance.pk, self.request.user.email, count,
        )
        instance.delete()


class TrustedClientViewSet(viewsets.ModelViewSet):
    """CRUD sur les apps autorisées à réclamer un jeton amont.

    Mêmes permissions que le coffre — et pour la même raison : ce sont deux
    facettes du même pouvoir. Qui peut réécrire l'`authorization_url` d'un site
    peut déjà détourner tout le lab ; lui refuser l'ajout d'un `client_id`
    n'ajouterait aucune garantie, seulement un aller-retour par le `.env`.

    La lecture est ouverte à tout compte authentifié comme pour les sites : la
    liste ne contient aucun secret, seulement des `client_id` d'apps du lab —
    valeurs déjà publiques, chaque SPA du lab exposant la sienne dans `env.js`.

    L'écriture demande **en plus** de venir de l'interface d'oauth-hub
    (`WritableFromHubOnly`) : une app tierce déjà autorisée ne doit pas pouvoir
    s'ajouter des complices avec le jeton d'un dev qui l'utilise.

    ⚠ Ce que cette classe ne fait PAS : décider qui est autorisé. Cette décision
    vit dans `TrustedClient.is_trusted`, qui reste la seule autorité et applique
    ses garde-fous même sur une ligne créée hors de cette API.
    """

    queryset = TrustedClient.objects.all()
    serializer_class = TrustedClientSerializer
    # IsAuthenticated d'abord — IsVaultAdminOrReadOnly laisse passer toute
    # méthode sûre sans regarder l'identité (cf. sa docstring). WritableFromHubOnly
    # ajoute la seule restriction propre à cette liste : on l'édite depuis
    # l'interface d'oauth-hub, pas au travers d'une app tierce autorisée.
    permission_classes = [IsAuthenticated, IsVaultAdminOrReadOnly, WritableFromHubOnly]
    lookup_field = 'client_id'
    lookup_value_regex = '[^/]+'

    def list(self, request, *args, **kwargs):
        """Liste des lignes, précédée de l'autorisation en dur d'oauth-hub.

        Cette page répond à la question « qui peut obtenir mes jetons amont ? » :
        en omettre le client d'oauth-hub lui-même donnerait une réponse fausse,
        alors même qu'il est le premier concerné (c'est lui qui sert cette
        interface). Marquée `locked`, la ligne se lit comme ce qu'elle est —
        une autorisation permanente, sans bouton pour la retirer.
        """
        response = super().list(request, *args, **kwargs)
        response.data = [
            {
                'client_id': settings.KEYCLOAK_CLIENT_ID,
                'description': (
                    "oauth-hub elle-même — l'interface que vous utilisez. "
                    "Toujours autorisée : sans elle, une liste vide "
                    "verrouillerait cette page."
                ),
                'enabled': True,
                'locked': True,
                'created_at': None,
                'updated_at': None,
                'updated_by': '',
            },
            *response.data,
        ]
        return response

    def perform_create(self, serializer):
        instance = serializer.save()
        logger.warning(
            "Client '%s' AUTORISÉ à demander des jetons amont, par %s.",
            instance.pk, self.request.user.email,
        )

    def perform_update(self, serializer):
        was_enabled = serializer.instance.enabled
        instance = serializer.save()
        if was_enabled != instance.enabled:
            logger.warning(
                "Client '%s' %s par %s.",
                instance.pk,
                'RÉACTIVÉ' if instance.enabled else 'DÉSACTIVÉ',
                self.request.user.email,
            )

    def perform_destroy(self, instance):
        logger.warning(
            "Client '%s' RÉVOQUÉ par %s — il ne peut plus demander de jeton amont.",
            instance.pk, self.request.user.email,
        )
        instance.delete()


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Utilisateur : relier et délier ses comptes
# ══════════════════════════════════════════════════════════════════════════════

class MyConnectionListView(APIView):
    """GET /api/connections/ — mes connexions, tous sites confondus."""

    def get(self, request):
        connections = (
            Connection.objects
            .filter(user_email=request.user.email)
            .select_related('provider')
        )
        return Response(ConnectionSerializer(connections, many=True).data)


class MyConnectionDetailView(APIView):
    """DELETE /api/connections/<slug>/ — délier un site.

    Supprime le jeton **de notre côté**. Ne révoque rien chez le site : la
    plupart n'exposent pas d'API de révocation utilisable avec ces
    identifiants, et prétendre le contraire donnerait un faux sentiment de
    sécurité. L'interface le dit à l'utilisateur, avec le lien vers la page de
    révocation du site.
    """

    def delete(self, request, slug: str):
        deleted, _ = Connection.objects.filter(
            provider_id=slug, user_email=request.user.email,
        ).delete()
        if not deleted:
            raise NotFound(f"Vous n'avez aucune connexion au site '{slug}'.")
        return Response(status=status.HTTP_204_NO_CONTENT)


class AuthorizeView(APIView):
    """GET /api/providers/<slug>/authorize/ — démarre l'aller-retour.

    Renvoie l'URL vers laquelle le navigateur doit partir, au lieu de rediriger
    directement : l'appelant est une requête `fetch()` authentifiée, une 302 y
    serait suivie par le navigateur en arrière-plan sans jamais montrer l'écran
    de consentement du site.

    Paramètres de requête :
      `return_url`  où renvoyer le navigateur une fois la connexion établie.
      `scopes`      portées supplémentaires (défaut : celles du site).
    """

    def get(self, request, slug: str):
        provider = _get_provider(slug, require_configured=True)

        return_url = request.GET.get('return_url', '')
        if not _is_safe_return_url(return_url):
            raise ValidationError(
                "`return_url` refusée : seules le domaine du lab et une adresse "
                "de boucle locale (127.0.0.1) sont acceptées."
            )

        PendingAuthorization.purge_expired()

        state = oauth.new_state()
        verifier = oauth.new_code_verifier() if provider.use_pkce else ''
        redirect_uri = _callback_uri(slug)

        PendingAuthorization.objects.create(
            state=state,
            provider=provider,
            user_email=request.user.email,
            redirect_uri=redirect_uri,
            code_verifier=verifier,
            return_url=return_url,
        )

        return Response({
            'authorization_url': oauth.build_authorization_url(
                provider,
                state=state,
                redirect_uri=redirect_uri,
                scopes=request.GET.get('scopes', ''),
                code_verifier=verifier,
            ),
            'expires_in': int(PendingAuthorization.TTL.total_seconds()),
        })


class CallbackView(APIView):
    """GET /api/callback/<slug>/ — retour du site.

    **Seul endpoint non authentifié de l'app**, et il ne peut pas en être
    autrement : c'est le site externe qui renvoie le navigateur ici, sans jeton
    Keycloak. Ce qui tient lieu d'authentification est le `state` : aléatoire,
    à usage unique, créé par une requête authentifiée et porteur de l'identité
    de celui qui a démarré le flux (cf. PendingAuthorization).
    """

    authentication_classes: list = []
    permission_classes = [AllowAny]

    def _fail(self, pending, message: str, code: str = 'error'):
        """Renvoie l'utilisateur là d'où il vient, avec l'erreur en clair.

        Un JSON brut serait illisible : à ce stade, c'est un navigateur qui est
        devant, pas un client d'API.

        `oauth_error_code` accompagne le message : une application cliente doit
        pouvoir décider quoi faire (réessayer ? prévenir un dev ?) sans avoir à
        faire correspondre du texte français, qui peut être reformulé.
        """
        target = (pending.return_url if pending and pending.return_url else '') \
            or settings.OAUTH_HUB_FRONTEND_PUBLIC_URL.rstrip('/') + '/providers'
        params = {'oauth_error': message, 'oauth_error_code': code}
        if pending is not None:
            params['provider'] = pending.provider_id
        separator = '&' if '?' in target else '?'
        return redirect(f'{target}{separator}{urlencode(params)}')

    def get(self, request, slug: str):
        state = request.GET.get('state', '')
        pending = PendingAuthorization.objects.filter(pk=state).select_related(
            'provider',
        ).first()

        if pending is None:
            # Ni `state` inconnu ni `state` rejoué ne doivent en dire plus : on
            # ne confirme pas à un tiers l'existence d'un flux en cours.
            return self._fail(None, "Requête de connexion inconnue ou déjà utilisée.",
                              "unknown_state")

        # Usage unique : consommé AVANT tout appel réseau, pour qu'un échec
        # d'échange ne laisse pas un état rejouable derrière lui.
        with transaction.atomic():
            PendingAuthorization.objects.filter(pk=state).delete()

        if pending.is_expired:
            return self._fail(pending, "Requête de connexion expirée — recommencez.",
                              "expired_state")
        if pending.provider_id != slug:
            return self._fail(pending, "Incohérence entre le site et la requête de connexion.",
                              "provider_mismatch")

        if request.GET.get('error'):
            return self._fail(pending, request.GET.get(
                'error_description', request.GET['error'],
            ), 'provider_refused')

        code = request.GET.get('code', '')
        if not code:
            return self._fail(pending, "Le site n'a renvoyé aucun code d'autorisation.",
                              "no_code")

        provider = pending.provider
        try:
            token = oauth.exchange_code(
                provider,
                code=code,
                redirect_uri=pending.redirect_uri,
                code_verifier=pending.code_verifier,
            )
        except oauth.OAuthError as exc:
            logger.warning(
                "Échange de code échoué pour %s sur '%s' : %s",
                pending.user_email, slug, exc,
            )
            return self._fail(pending, str(exc), 'exchange_failed')

        label = oauth.fetch_account_label(provider, token.access_token)

        connection, _ = Connection.objects.get_or_create(
            provider=provider, user_email=pending.user_email,
            defaults={'access_token_encrypted': ''},
        )
        connection.access_token = token.access_token
        # Un site qui ne renvoie pas de refresh_token lors d'un renouvellement
        # ne doit pas effacer celui qu'on détient déjà (comportement courant
        # côté Google : le refresh_token n'est émis qu'à la première
        # autorisation).
        if token.refresh_token:
            connection.refresh_token = token.refresh_token
        connection.token_type = token.token_type
        connection.scope = token.scope
        connection.expires_at = token.expires_at
        connection.account_label = label or connection.account_label
        connection.save()

        logger.info("Connexion '%s' établie pour %s.", slug, pending.user_email)

        target = pending.return_url or (
            settings.OAUTH_HUB_FRONTEND_PUBLIC_URL.rstrip('/') + '/providers'
        )
        separator = '&' if '?' in target else '?'
        return redirect(
            f'{target}{separator}{urlencode(_return_params(provider, connection))}'
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Apps tierces : le jeton amont
# ══════════════════════════════════════════════════════════════════════════════

class TokenView(APIView):
    """GET /api/providers/<slug>/token/ — le jeton amont de l'utilisateur courant.

    **C'est le seul endroit de l'app qui renvoie un jeton amont.** L'appelant
    est authentifié par son jeton Keycloak ; le jeton rendu est celui de la
    personne derrière ce jeton, jamais celui d'une autre.

    Rappel de ce que ça donne à l'appelant : le jeton brut du site. Toute app
    qui l'obtient agit sur GitHub (ou ailleurs) au nom de l'utilisateur, avec
    les portées accordées. C'est pourquoi la liste des clients autorisés
    (`KEYCLOAK_TRUSTED_CLIENTS`) est explicite, app par app, et jamais ouverte
    à tout le realm.

    Réponses :
      200  {access_token, token_type, scope, expires_at}
      409  aucune connexion (ou expirée sans moyen de la renouveler),
           avec `connect_url` : l'app peut y envoyer son utilisateur.
    """

    def get(self, request, slug: str):
        provider = _get_provider(slug)
        return_url = request.GET.get('return_url', '')
        if not _is_safe_return_url(return_url):
            return_url = ''

        connection = Connection.objects.filter(
            provider=provider, user_email=request.user.email,
        ).select_related('provider').first()

        if connection is None:
            return Response(
                {
                    'detail': (
                        f"Vous n'avez pas encore relié votre compte {provider.display_name}."
                    ),
                    'provider': slug,
                    'connect_url': _connect_url(slug, return_url),
                },
                status=status.HTTP_409_CONFLICT,
            )

        if connection.is_expired:
            renewed = self._try_refresh(provider, connection)
            if not renewed:
                return Response(
                    {
                        'detail': (
                            f"Votre connexion à {provider.display_name} a expiré "
                            "et n'a pas pu être renouvelée automatiquement."
                        ),
                        'provider': slug,
                        'connect_url': _connect_url(slug, return_url),
                    },
                    status=status.HTTP_409_CONFLICT,
                )

        logger.info(
            "Jeton '%s' remis à l'app '%s' pour %s.",
            slug, request.user.client_id, request.user.email,
        )
        return Response({
            'access_token': connection.access_token,
            'token_type': connection.token_type,
            'scope': connection.scope,
            'expires_at': connection.expires_at,
        })

    @staticmethod
    def _try_refresh(provider: Provider, connection: Connection) -> bool:
        if not connection.refresh_token_encrypted:
            return False
        try:
            token = oauth.refresh_access_token(
                provider, refresh_token=connection.refresh_token,
            )
        except oauth.OAuthError as exc:
            logger.warning(
                "Renouvellement '%s' échoué pour %s : %s",
                provider.pk, connection.user_email, exc,
            )
            return False
        connection.access_token = token.access_token
        if token.refresh_token:
            connection.refresh_token = token.refresh_token
        connection.token_type = token.token_type or connection.token_type
        connection.scope = token.scope or connection.scope
        connection.expires_at = token.expires_at
        connection.save()
        return True


class ProviderStatusView(APIView):
    """GET /api/providers/<slug>/status/ — suis-je relié à ce site ?

    Permet à une app tierce de savoir si elle peut compter sur le jeton
    **sans le demander** — donc sans le faire transiter, ni le journaliser, pour
    un simple affichage (« Connecté à GitHub ✓ »).
    """

    def get(self, request, slug: str):
        provider = _get_provider(slug)
        connection = Connection.objects.filter(
            provider=provider, user_email=request.user.email,
        ).first()
        return Response({
            'provider': slug,
            'display_name': provider.display_name,
            'configured': provider.is_configured,
            'connected': connection is not None and not connection.is_expired,
            'scope': connection.scope if connection else '',
            'account_label': connection.account_label if connection else '',
            'connect_url': _connect_url(slug, request.GET.get('return_url', '')),
        })
