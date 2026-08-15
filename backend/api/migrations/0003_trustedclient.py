"""Sort la liste blanche `azp` du `.env` pour la mettre en base.

La liste des apps autorisées à réclamer un jeton amont vivait dans
`KEYCLOAK_TRUSTED_CLIENTS` (`oauth-hub/.env`) : l'ajouter ou la retirer
demandait d'éditer un fichier sur l'hôte puis de recréer le conteneur. Deux
conséquences, l'une pénible et l'autre franchement mauvaise : personne d'autre
que celui qui a accès à l'hôte ne pouvait autoriser une app, et surtout une
**révocation** demandait la même cérémonie — donc était remise à plus tard.

Cette migration reprend la valeur du `.env` telle quelle, pour qu'aucune app
autorisée aujourd'hui ne se retrouve refusée au redémarrage. Ce qui est écarté
au passage :

  • le client d'oauth-hub lui-même, désormais autorisé en dur (cf.
    `TrustedClient.is_trusted`) — une ligne pour lui serait supprimable, donc un
    verrouillage possible de l'interface ;
  • les clients intégrés du realm (`RESERVED_CLIENT_IDS`), qui n'auraient jamais
    dû y figurer et que le modèle refuse de toute façon d'honorer.

Le `.env` n'est pas modifié : sa valeur devient sans effet à l'exécution, ce qui
est documenté dans `settings.py` et `.env.example`. Une réexécution éventuelle
(base recréée) repartira de la même graine.
"""
from django.conf import settings
from django.db import migrations, models

# Recopié plutôt qu'importé de api.models : une migration doit rester lisible et
# rejouable telle qu'elle a été écrite, même si le modèle évolue ensuite.
RESERVED = {
    'admin-cli', 'security-admin-console', 'account',
    'account-console', 'broker', 'realm-management',
}


def seed_from_env(apps, schema_editor):
    TrustedClient = apps.get_model('api', 'TrustedClient')
    seed = getattr(settings, 'KEYCLOAK_TRUSTED_CLIENTS_SEED', set())
    for client_id in sorted(seed):
        if client_id == settings.KEYCLOAK_CLIENT_ID or client_id in RESERVED:
            continue
        TrustedClient.objects.get_or_create(
            client_id=client_id,
            defaults={
                'description': 'Reprise de KEYCLOAK_TRUSTED_CLIENTS (oauth-hub/.env).',
                'enabled': True,
            },
        )


def unseed(apps, schema_editor):
    """Rien à défaire : la table entière disparaît avec la migration."""


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_seed_providers'),
    ]

    operations = [
        migrations.CreateModel(
            name='TrustedClient',
            fields=[
                ('client_id', models.CharField(
                    help_text="Le `client_id` Keycloak de l'app appelante, tel quel.",
                    max_length=255, primary_key=True, serialize=False,
                )),
                ('description', models.CharField(
                    blank=True,
                    help_text="À quoi sert cette app, et qui l'a demandée.",
                    max_length=255,
                )),
                ('enabled', models.BooleanField(
                    default=True,
                    help_text=(
                        "Décocher coupe l'accès immédiatement sans perdre la fiche — "
                        "préférable à une suppression pour une coupure temporaire."
                    ),
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('updated_by', models.EmailField(blank=True, max_length=255)),
            ],
            options={
                'db_table': 'trusted_clients',
                'ordering': ['client_id'],
            },
        ),
        migrations.RunPython(seed_from_env, unseed),
    ]
