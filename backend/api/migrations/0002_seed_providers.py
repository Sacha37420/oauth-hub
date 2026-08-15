"""Pré-remplit trois sites courants — sans aucun identifiant.

Ce que cette migration apporte : les URLs d'autorisation et de jeton, le
séparateur de portées et le support PKCE de chaque site. C'est exactement la
partie qu'un dev ne peut pas deviner et qui se recopie mal.

Ce qu'elle n'apporte pas, volontairement : `client_id` et `client_secret`
restent vides. Un site sans identifiants n'est pas connectable
(`Provider.is_configured`), il apparaît simplement dans l'interface comme « à
configurer ». Aucun secret ne peut donc entrer dans le dépôt par cette voie.

Un dev qui n'a besoin d'aucun de ces trois sites peut les supprimer depuis
l'interface : la migration ne les recrée pas.
"""
from django.db import migrations

SEEDS = [
    {
        'slug': 'github',
        'display_name': 'GitHub',
        'authorization_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'default_scopes': 'read:user repo',
        'scope_separator': ' ',
        # Les OAuth Apps GitHub n'acceptent pas PKCE (seules les GitHub Apps
        # récentes le font) — l'activer ferait échouer l'autorisation.
        'use_pkce': False,
        'account_url': 'https://api.github.com/user',
        'account_label_field': 'login',
        'notes': (
            "Enregistrer l'application sur https://github.com/settings/developers "
            "→ OAuth Apps → New OAuth App, puis coller ici le Client ID et le "
            "Client Secret. L'« Authorization callback URL » doit être exactement "
            "l'URI de rappel affichée en haut de cette fiche.\n"
            "⚠ Le jeton délivré par une OAuth App n'expire pas : voir la section "
            "« Limite connue » du README de l'app."
        ),
    },
    {
        'slug': 'gitlab',
        'display_name': 'GitLab',
        'authorization_url': 'https://gitlab.com/oauth/authorize',
        'token_url': 'https://gitlab.com/oauth/token',
        'default_scopes': 'read_user read_repository',
        'scope_separator': ' ',
        'use_pkce': True,
        'account_url': 'https://gitlab.com/api/v4/user',
        'account_label_field': 'username',
        'notes': (
            "Enregistrer l'application dans GitLab → Preferences → Applications. "
            "GitLab émet des jetons courts avec refresh_token : le renouvellement "
            "est automatique côté oauth-hub."
        ),
    },
    {
        'slug': 'google',
        'display_name': 'Google',
        'authorization_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'default_scopes': (
            'https://www.googleapis.com/auth/userinfo.email '
            'https://www.googleapis.com/auth/userinfo.profile'
        ),
        'scope_separator': ' ',
        'use_pkce': True,
        'account_url': 'https://www.googleapis.com/oauth2/v3/userinfo',
        'account_label_field': 'email',
        'notes': (
            "Console Google Cloud → API et services → Identifiants → ID client "
            "OAuth 2.0 (type « Application Web »).\n"
            "⚠ Google n'émet un refresh_token QUE si l'URL d'autorisation porte "
            "access_type=offline&prompt=consent — à ajouter à la fin de l'URL "
            "d'autorisation ci-dessus si des jetons durables sont nécessaires."
        ),
    },
]


def seed(apps, schema_editor):
    Provider = apps.get_model('api', 'Provider')
    for entry in SEEDS:
        # get_or_create et non create : une reprise de migration sur une base
        # déjà peuplée ne doit rien écraser (un dev a pu ajuster les URLs).
        Provider.objects.get_or_create(slug=entry['slug'], defaults=entry)


def unseed(apps, schema_editor):
    """Ne supprime que les fiches restées vierges.

    Un site où un dev a déposé des identifiants n'est plus « la graine » : le
    retrait de la migration ne doit pas emporter une configuration réelle ni
    les connexions utilisateurs qui en dépendent (cascade).
    """
    Provider = apps.get_model('api', 'Provider')
    Provider.objects.filter(
        slug__in=[e['slug'] for e in SEEDS], client_id='',
        client_secret_encrypted='',
    ).delete()


class Migration(migrations.Migration):

    dependencies = [('api', '0001_initial')]

    operations = [migrations.RunPython(seed, unseed)]
