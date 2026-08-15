"""Authentification Keycloak — Verrou 2 (serrure de l'API) pour oauth-hub.

Deux écarts assumés par rapport au template, tous deux dictés par le rôle de
cette app :

1. **`azp` contre une liste blanche** et non contre un client unique. Toute la
   raison d'être d'oauth-hub est d'être appelée par d'AUTRES apps au nom de
   leurs utilisateurs : leur frontend obtient un jeton dont `azp` est leur
   propre client_id, jamais `oauth-hub`. Même mécanisme que `storage`
   (KEYCLOAK_TRUSTED_CLIENTS, cf. CLAUDE.md) — et même propriété de sécurité
   préservée : `admin-cli` n'y figure jamais, donc le password grant ouvert par
   défaut sur le realm ne donne accès à rien ici.

2. **« au moins un groupe »** plutôt qu'un groupe nommé. La règle voulue est :
   tout compte réellement rattaché au lab peut connecter ses propres comptes
   externes ; un compte fraîchement auto-inscrit, qui n'a encore aucun groupe,
   n'accède à rien. `create-app-client.sh` reçoit donc la liste complète des
   groupes du realm dans `--require-group`, ce qui donne la même sémantique
   côté navigateur (Verrou 1) sans inventer de mécanisme parallèle.

   ⚠ Conséquence de maintenance : **un nouveau groupe LDAP doit être ajouté à
   `KEYCLOAK_REQUIRED_GROUPS` (et à `.keycloak-client-opts`)**, sinon ses
   membres seront refusés ici alors qu'ils sont bien rattachés au lab.
"""
import jwt
from jwt import PyJWKClient, InvalidTokenError
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings


class KeycloakUser:
    """Identité construite depuis les claims du JWT Keycloak."""

    is_authenticated = True
    is_active = True

    def __init__(self, claims: dict) -> None:
        self.email: str = claims.get('email', '')
        self.username: str = claims.get('preferred_username', self.email)
        self.groups: list[str] = list(claims.get('groups') or [])
        self.claims = claims
        # `azp` est conservé : les vues en ont besoin pour tracer QUELLE app a
        # demandé un jeton amont (cf. TokenView), information qui disparaîtrait
        # si on ne gardait que l'identité humaine.
        self.client_id: str = claims.get('azp', '')
        self.pk = self.email

    def __str__(self) -> str:
        return self.username

    @property
    def is_vault_admin(self) -> bool:
        """Droit de déposer/modifier les identifiants d'un site.

        Distinct de « peut utiliser l'app » : tout membre du lab connecte ses
        propres comptes, seuls les devs touchent aux identifiants partagés.
        """
        admin_groups = {
            g.strip() for g in settings.OAUTH_HUB_ADMIN_GROUPS.split(',') if g.strip()
        }
        return bool(admin_groups & set(self.groups))


class KeycloakJWTAuthentication(BaseAuthentication):
    """Valide un Bearer JWT Keycloak via le JWKS du realm."""

    _jwks_client: PyJWKClient | None = None

    @classmethod
    def _get_jwks_client(cls) -> PyJWKClient:
        if cls._jwks_client is None:
            jwks_uri = (
                f'{settings.KEYCLOAK_ISSUER_URI}'
                '/protocol/openid-connect/certs'
            )
            cls._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
        return cls._jwks_client

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            # Pas de repli sur ?token= ici, contrairement à `storage` : aucune
            # réponse de cette API n'est destinée à une balise <img> ou à un
            # loader tiers, et un jeton amont GitHub n'a rien à faire dans une
            # URL (journaux d'accès, Referer, historique du navigateur).
            return None
        token = auth_header[7:]

        try:
            client = self._get_jwks_client()
            signing_key = client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=['RS256'],
                options={
                    'verify_exp': True,
                    # L'audience varie selon le client Keycloak appelant ; c'est
                    # `azp` qui porte le contrôle, cf. docstring du module.
                    'verify_aud': False,
                },
            )
        except InvalidTokenError as exc:
            raise AuthenticationFailed(f'Token invalide : {exc}') from exc

        azp = claims.get('azp')
        if azp not in settings.KEYCLOAK_TRUSTED_CLIENTS:
            raise AuthenticationFailed(
                f"Ce token a été émis par un client non autorisé : '{azp}'. "
                "Ajoutez ce client_id à KEYCLOAK_TRUSTED_CLIENTS dans "
                "oauth-hub/.env pour l'autoriser à demander des jetons amont."
            )

        # Cloisonnement : au moins un groupe en commun. La liste vient de
        # KEYCLOAK_REQUIRED_GROUPS, renseignée par create-app-client.sh à partir
        # de --require-group. Vide ⇒ aucun filtre, ce qui serait une régression
        # de sécurité pour CETTE app : on le refuse explicitement plutôt que de
        # laisser passer tout le realm en silence.
        required = {
            g.strip() for g in settings.KEYCLOAK_REQUIRED_GROUPS.split(',') if g.strip()
        }
        if not required:
            raise AuthenticationFailed(
                "KEYCLOAK_REQUIRED_GROUPS est vide dans oauth-hub/.env : cette "
                "app distribuerait des jetons à tout compte du realm, y compris "
                "un compte auto-inscrit sans aucun groupe. Relancez "
                "create-app-client.sh avec --require-group."
            )

        groups = set(claims.get('groups') or [])
        if not (required & groups):
            raise AuthenticationFailed(
                "Accès réservé aux comptes rattachés à au moins un groupe du "
                "lab. Demandez à un administrateur de vous ajouter à un groupe."
            )

        if not claims.get('email'):
            raise AuthenticationFailed(
                "Le token ne contient pas de claim 'email'. Sans identité "
                "stable, impossible de rattacher un jeton amont à une personne."
            )

        return KeycloakUser(claims), token
