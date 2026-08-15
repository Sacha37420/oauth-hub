"""Permissions — la frontière entre « utiliser » et « administrer » le coffre.

Deux populations, à ne pas confondre :

  Tout membre du lab   connecte SES propres comptes externes et lit SES propres
                       jetons. C'est l'usage courant.
  Les devs             déposent et modifient les identifiants OAuth d'un site
                       (client_id/client_secret), qui sont partagés par tout le
                       lab. Une erreur ici casse la connexion de tout le monde,
                       et le secret déposé engage le lab entier auprès du site.
"""
from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsVaultAdmin(BasePermission):
    """Réservé aux membres d'un groupe de OAUTH_HUB_ADMIN_GROUPS ('developers')."""

    message = (
        "Seuls les membres du groupe des développeurs peuvent modifier les "
        "identifiants OAuth d'un site."
    )

    def has_permission(self, request, view) -> bool:
        return bool(getattr(request.user, 'is_vault_admin', False))


class IsVaultAdminOrReadOnly(BasePermission):
    """Lecture pour tout membre du lab **authentifié**, écriture pour les devs.

    La lecture est ouverte au-delà des devs parce que la représentation d'un
    Provider est délibérément **sans secret** (cf. ProviderSerializer) : slug,
    nom, portées et état de configuration. Un utilisateur doit pouvoir voir
    quels sites sont connectables sans être dev.

    ⚠ « Ouverte » s'arrête aux comptes authentifiés. Cette classe est déclarée
    en second dans `permission_classes`, DERRIÈRE `IsAuthenticated` : seule,
    elle rendrait la liste des sites lisible **anonymement** (slugs, client_id,
    URI de rappel, et les e-mails de `updated_by`), puisqu'elle répond True à
    toute méthode sûre sans jamais regarder l'identité. Ne pas l'utiliser seule.
    """

    message = IsVaultAdmin.message

    def has_permission(self, request, view) -> bool:
        if request.method in SAFE_METHODS:
            return True
        return bool(getattr(request.user, 'is_vault_admin', False))
