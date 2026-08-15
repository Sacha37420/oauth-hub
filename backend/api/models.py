"""Modèles du coffre OAuth.

Quatre objets, et une règle de cardinalité qui structure toute l'app :

  Provider              un SITE (github.com, gitlab.com…) — les identifiants
                        OAuth appartiennent au site, JAMAIS à l'app qui veut
                        s'y authentifier. Une seule app OAuth GitHub est
                        enregistrée pour tout le lab ; dix apps consommatrices
                        se partagent le même `client_id`/`client_secret`.
  Connection            le jeton d'UN utilisateur du lab pour UN site.
  PendingAuthorization  l'état éphémère d'un aller-retour vers le site.
  TrustedClient         une app du lab autorisée à réclamer un jeton amont.
"""
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from . import crypto


class Provider(models.Model):
    """Un site OAuth2 et les identifiants que le lab y a enregistrés.

    Volontairement générique (URLs d'autorisation et de jeton en base, pas de
    branche `if slug == 'github'` nulle part) : ajouter GitLab ou Google doit
    être une saisie de formulaire par un dev, pas un déploiement de code.
    """

    slug = models.SlugField(
        primary_key=True, max_length=64,
        help_text="Identifiant court utilisé dans les URLs : 'github', 'gitlab'…",
    )
    display_name = models.CharField(max_length=120)
    authorization_url = models.URLField(
        max_length=500,
        help_text="Ex. https://github.com/login/oauth/authorize",
    )
    token_url = models.URLField(
        max_length=500,
        help_text="Ex. https://github.com/login/oauth/access_token",
    )
    client_id = models.CharField(max_length=255)
    # Chiffré au repos — cf. api/crypto.py. Le nom de colonne dit explicitement
    # « encrypted » pour qu'un coup d'œil au schéma SQL ne laisse aucun doute.
    client_secret_encrypted = models.TextField(blank=True, default='')
    default_scopes = models.CharField(
        max_length=500, blank=True,
        help_text="Portées demandées par défaut, séparées par des espaces.",
    )
    scope_separator = models.CharField(
        max_length=4, default=' ',
        help_text="Séparateur attendu par le site dans le paramètre `scope`.",
    )
    use_pkce = models.BooleanField(
        default=False,
        help_text=(
            "Ajoute PKCE S256 à l'aller-retour avec le site. GitHub ne le "
            "supporte pas pour les OAuth Apps ; GitLab et Google, oui."
        ),
    )
    account_url = models.URLField(
        max_length=500, blank=True,
        help_text=(
            "Optionnel — endpoint renvoyant le profil du compte connecté "
            "(ex. https://api.github.com/user). Sert uniquement à afficher à "
            "l'utilisateur QUEL compte il a relié."
        ),
    )
    account_label_field = models.CharField(
        max_length=64, blank=True, default='login',
        help_text="Champ JSON de la réponse `account_url` à afficher ('login', 'email'…).",
    )
    enabled = models.BooleanField(default=True)
    notes = models.TextField(
        blank=True,
        help_text="Aide-mémoire pour les devs : où l'app est enregistrée, par qui…",
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.EmailField(max_length=255, blank=True)

    class Meta:
        db_table = 'providers'
        ordering = ['slug']

    def __str__(self) -> str:
        return self.display_name or self.slug

    # ── Secret : jamais manipulé en clair par les vues ────────────────────────
    @property
    def client_secret(self) -> str:
        return crypto.decrypt(self.client_secret_encrypted)

    @client_secret.setter
    def client_secret(self, value: str) -> None:
        self.client_secret_encrypted = crypto.encrypt(value or '')

    @property
    def has_client_secret(self) -> bool:
        return bool(self.client_secret_encrypted)

    @property
    def is_configured(self) -> bool:
        """Utilisable pour une vraie connexion.

        Un Provider créé sans secret est légitime — un dev peut déposer l'URL et
        le client_id, puis revenir coller le secret. Il ne doit simplement pas
        apparaître comme connectable aux utilisateurs.
        """
        return bool(self.client_id and self.has_client_secret and self.enabled)

    def scopes_as_param(self, scopes: str = '') -> str:
        """Assemble le paramètre `scope` avec le séparateur attendu par le site."""
        raw = (scopes or self.default_scopes or '').split()
        # Défense en profondeur : une fiche héritée d'un import ou d'une
        # migration pourrait porter un séparateur vide, qui collerait les
        # portées entre elles au lieu de les séparer.
        return (self.scope_separator or ' ').join(raw)


class Connection(models.Model):
    """Le jeton amont d'un utilisateur du lab pour un site.

    Un enregistrement par (site, utilisateur) : le jeton appartient à la
    personne, pas à l'app qui le demande. C'est ce qui permet à `storage_analysis`
    et à une app web du lab de réutiliser la même connexion GitHub sans que
    l'utilisateur ait à la refaire deux fois.
    """

    provider = models.ForeignKey(
        Provider, on_delete=models.CASCADE, related_name='connections',
    )
    user_email = models.EmailField(max_length=255)
    access_token_encrypted = models.TextField()
    refresh_token_encrypted = models.TextField(blank=True, default='')
    token_type = models.CharField(max_length=40, default='bearer')
    scope = models.CharField(max_length=500, blank=True)
    # NULL ⇒ le site n'a pas annoncé d'expiration. C'est le cas d'une OAuth App
    # GitHub, dont le jeton est durable — voir la limite documentée dans le
    # README de l'app (section « Limite connue »).
    expires_at = models.DateTimeField(null=True, blank=True)
    account_label = models.CharField(
        max_length=200, blank=True,
        help_text="Identité côté site (login GitHub…), pour affichage seulement.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'connections'
        ordering = ['provider_id', 'user_email']
        constraints = [
            models.UniqueConstraint(
                fields=['provider', 'user_email'], name='uniq_connection_per_user_provider',
            ),
        ]

    def __str__(self) -> str:
        return f'{self.user_email} → {self.provider_id}'

    @property
    def access_token(self) -> str:
        return crypto.decrypt(self.access_token_encrypted)

    @access_token.setter
    def access_token(self, value: str) -> None:
        self.access_token_encrypted = crypto.encrypt(value or '')

    @property
    def refresh_token(self) -> str:
        return crypto.decrypt(self.refresh_token_encrypted)

    @refresh_token.setter
    def refresh_token(self, value: str) -> None:
        self.refresh_token_encrypted = crypto.encrypt(value or '')

    @property
    def is_expired(self) -> bool:
        """Marge de 60 s : un jeton qui expire pendant le trajet réseau vers le
        site consommateur doit être considéré comme déjà mort ici."""
        if self.expires_at is None:
            return False
        return timezone.now() >= self.expires_at - timedelta(seconds=60)


class PendingAuthorization(models.Model):
    """Le `state` d'un aller-retour en cours, et à qui il appartient.

    **C'est la pièce de sécurité du flux.** Le site renvoie le navigateur sur
    `/api/callback/<slug>/` sans aucun jeton Keycloak — cette requête-là est
    forcément anonyme. Sans état côté serveur, rien ne dirait à qui rattacher
    le jeton obtenu, et n'importe qui pourrait faire déposer son propre jeton
    GitHub dans le compte d'un autre (ou l'inverse : se faire attribuer le
    jeton d'autrui) en rejouant une URL de callback.

    D'où : `state` aléatoire, lié à l'utilisateur authentifié qui a démarré le
    flux, à usage unique (supprimé à la consommation) et à durée de vie courte.
    """

    TTL = timedelta(minutes=10)

    state = models.CharField(primary_key=True, max_length=64)
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    user_email = models.EmailField(max_length=255)
    # L'URI exacte envoyée au site à l'aller : le site la revérifie à l'échange,
    # elle doit donc être rejouée à l'identique et non recalculée.
    redirect_uri = models.URLField(max_length=500)
    code_verifier = models.CharField(max_length=128, blank=True)
    return_url = models.URLField(
        max_length=500, blank=True,
        help_text="Où renvoyer le navigateur une fois la connexion établie.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pending_authorizations'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'{self.user_email} → {self.provider_id} ({self.state[:8]}…)'

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.created_at + self.TTL

    @classmethod
    def purge_expired(cls) -> int:
        """Supprime les états périmés.

        Appelée à chaque démarrage de flux plutôt que par une tâche planifiée :
        la table est minuscule et l'app n'a pas de Celery. Un état périmé n'est
        pas dangereux (il est refusé à la consommation), juste encombrant.
        """
        cutoff = timezone.now() - cls.TTL
        deleted, _ = cls.objects.filter(created_at__lt=cutoff).delete()
        return deleted


class TrustedClient(models.Model):
    """Une app du lab autorisée à réclamer les jetons amont de ses utilisateurs.

    C'est la liste blanche `azp` du Verrou 2 (cf. api/authentication.py), sortie
    du `.env` pour vivre en base et être tenue depuis l'interface par les mêmes
    devs qui déposent les identifiants des sites.

    **Pourquoi ce n'est pas un affaiblissement.** La population qui édite cette
    table (`OAUTH_HUB_ADMIN_GROUPS`, cf. permissions.IsVaultAdmin) détient déjà
    strictement plus : elle écrit `client_id`/`client_secret` et surtout
    `authorization_url`/`token_url` de chaque Provider — donc elle peut déjà
    détourner l'aller-retour OAuth de tout le lab vers un site qu'elle contrôle.
    Autoriser un client de plus ne lui ouvre rien qu'elle ne puisse déjà obtenir.
    Ce qui change, c'est le **délai** : autoriser ou surtout **révoquer** une app
    ne demande plus d'éditer un `.env` et de recréer un conteneur, ce qui rend la
    révocation immédiate au lieu d'être remise à plus tard.

    Trois invariants tiennent la propriété de sécurité, et aucun n'est éditable :

    1. **Le client d'oauth-hub lui-même est toujours autorisé**, en dur, sans
       ligne en base — sinon une suppression malheureuse verrouillerait
       l'interface qui sert à réparer la liste. Il n'y a donc aucun état d'où on
       ne puisse pas revenir.
    2. **`RESERVED_CLIENT_IDS` n'est jamais autorisable**, et le filtre est
       appliqué ici — pas seulement dans le sérialiseur : une ligne insérée
       directement en base (psql, fixture, import) reste inerte. C'est ce qui
       préserve mot pour mot la règle du lab « `admin-cli` n'y figure jamais »,
       le realm l'exposant en client public avec password grant.
    3. **Aucun cache.** La vérification lit la table à chaque requête : un PK
       lookup sur une table d'une poignée de lignes, contre une révocation qui
       prend effet à la requête suivante. Un cache mémoire, même court, serait
       par processus gunicorn — donc une révocation resterait partiellement sans
       effet pendant sa durée, silencieusement.
    """

    #: Clients intégrés du realm — jamais des apps du lab, et `admin-cli` est
    #: l'exact contournement contre lequel le contrôle `azp` existe.
    RESERVED_CLIENT_IDS = frozenset({
        'admin-cli',
        'security-admin-console',
        'account',
        'account-console',
        'broker',
        'realm-management',
    })

    client_id = models.CharField(
        primary_key=True, max_length=255,
        help_text="Le `client_id` Keycloak de l'app appelante, tel quel.",
    )
    description = models.CharField(
        max_length=255, blank=True,
        help_text="À quoi sert cette app, et qui l'a demandée.",
    )
    enabled = models.BooleanField(
        default=True,
        help_text=(
            "Décocher coupe l'accès immédiatement sans perdre la fiche — "
            "préférable à une suppression pour une coupure temporaire."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.EmailField(max_length=255, blank=True)

    class Meta:
        db_table = 'trusted_clients'
        ordering = ['client_id']

    def __str__(self) -> str:
        return self.client_id

    @classmethod
    def is_trusted(cls, azp: str) -> bool:
        """Ce client a-t-il le droit d'appeler cette API ?

        Ordre volontaire : le socle en dur d'abord (l'interface d'oauth-hub
        répond même si la table est vide), la liste réservée ensuite (elle prime
        sur toute ligne en base), la base en dernier.
        """
        if not azp:
            return False
        if azp == settings.KEYCLOAK_CLIENT_ID:
            return True
        if azp in cls.RESERVED_CLIENT_IDS:
            return False
        return cls.objects.filter(pk=azp, enabled=True).exists()
