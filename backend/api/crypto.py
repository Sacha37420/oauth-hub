"""Chiffrement au repos des secrets du coffre.

Deux familles de secrets vivent dans cette base : le `client_secret` de chaque
site OAuth (déposé par un dev) et le jeton amont de chaque utilisateur. Les
deux sont chiffrés avec la même clé Fernet, lue dans OAUTH_HUB_ENCRYPTION_KEY.

**Pourquoi chiffrer alors qu'aucune base du lab n'est exposée** : cette app
concentre, dans un seul schéma de l'instance PostgreSQL *partagée*, de quoi
agir sur GitHub (et demain ailleurs) au nom de tous les comptes du lab. Une
sauvegarde de `devdb` qui fuit, ou un `search_path` mal cloisonné depuis une
autre app, suffirait sinon à tout rejouer immédiatement. La clé, elle, ne vit
que dans `oauth-hub/.env` — jamais en base, jamais dans une sauvegarde SQL.

Ce que ça ne protège **pas**, et qu'il ne faut pas se raconter : un attaquant
qui obtient un shell dans le conteneur `oauth-hub-backend` lit la clé dans
l'environnement et déchiffre tout. Le chiffrement au repos couvre la fuite de
données froides (dump, volume, sauvegarde), pas la compromission du service.
"""
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from cryptography.fernet import Fernet, InvalidToken

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Instancie Fernet une fois par process, à la première utilisation.

    Volontairement paresseux plutôt qu'au chargement du module : `manage.py
    migrate` et `collectstatic` doivent pouvoir tourner sur un déploiement dont
    la clé n'est pas encore renseignée. C'est seulement au premier secret lu ou
    écrit que l'absence de clé devient une vraie erreur.
    """
    global _fernet
    if _fernet is None:
        key = (settings.OAUTH_HUB_ENCRYPTION_KEY or '').strip()
        if not key:
            raise ImproperlyConfigured(
                "OAUTH_HUB_ENCRYPTION_KEY est vide dans oauth-hub/.env. "
                "Générez-la avec : "
                "python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\" "
                "(ou relancez scripts/init-secrets.sh)."
            )
        try:
            _fernet = Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            raise ImproperlyConfigured(
                f"OAUTH_HUB_ENCRYPTION_KEY invalide : {exc}. "
                "Une clé Fernet est une chaîne base64 urlsafe de 44 caractères."
            ) from exc
    return _fernet


def encrypt(value: str) -> str:
    """Chiffre une valeur. Une chaîne vide reste une chaîne vide.

    Ce cas « vide » n'est pas un raccourci : il distingue « pas de secret
    enregistré » (client_secret jamais déposé, refresh_token absent) de « secret
    enregistré » sans avoir à ajouter une colonne nullable à chaque champ.
    """
    if not value:
        return ''
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Déchiffre une valeur produite par `encrypt`.

    Lève ValueError sur un jeton illisible — ce qui, en pratique, signifie
    presque toujours que OAUTH_HUB_ENCRYPTION_KEY a changé depuis l'écriture
    (rotation de secrets sans reprise des données). On préfère l'erreur franche
    au silence : rendre '' ferait croire à l'appelant que l'utilisateur n'a
    jamais connecté le site, et déclencherait une reconnexion qui écraserait un
    jeton encore valide.
    """
    if not value:
        return ''
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Secret illisible : la clé OAUTH_HUB_ENCRYPTION_KEY ne correspond "
            "pas à celle utilisée pour le chiffrer."
        ) from exc
