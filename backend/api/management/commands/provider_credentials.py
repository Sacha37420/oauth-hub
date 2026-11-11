"""État et dépôt des identifiants d'un site OAuth, sans passer par l'interface.

Sert à `scripts/install.sh` (remplir la fiche GitHub à la fin d'une installation)
et à `scripts/lab-doctor.sh` (dire si elle est utilisable). Lancée par :

    docker exec oauth-hub-backend python manage.py provider_credentials status github
    printf '%s\\n' "$secret" | docker exec -i oauth-hub-backend \\
        python manage.py provider_credentials set github --client-id <id>

Contrat (chantier « nuit-auto », interface I1) :
  • stdout : exactement une ligne JSON, rien d'autre ; tout message humain sur stderr ;
  • codes : 0 configurée / écrite · 2 usage · 3 fiche incomplète ou désactivée
    (status) · 4 fiche absente ;
  • le `client_secret` n'est lu QUE sur stdin (première ligne, fin de ligne
    retirée), jamais en argument, et n'apparaît sur aucune sortie ni journal.

Pourquoi les erreurs d'arguments sont réécrites : argparse recopie dans son
message l'argument fautif (« unrecognized arguments: … »). Quelqu'un qui
passerait le secret en argument par erreur le verrait donc ressortir sur
stderr, puis dans un journal d'installation. Le message est ici fixe.
"""
from __future__ import annotations

import json
import re
import sys

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError, CommandParser

from api.models import Provider
from api.views import _callback_uri

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_ABSENT = 4

# Même alphabet que le SlugField du modèle (validate_slug de Django).
_SLUG = re.compile(r'^[-a-zA-Z0-9_]{1,64}$')

_USAGE_MESSAGE = 'arguments invalides (voir --help) — le secret se donne sur stdin, jamais en argument'


def _safe_error(parser: CommandParser, message: str) -> None:
    """Remplace `parser.error` : code 2, sans jamais recopier les arguments."""
    parser.print_usage(sys.stderr)
    sys.stderr.write(f'{parser.prog}: erreur : {_USAGE_MESSAGE}\n')
    sys.exit(EXIT_USAGE)


class _SafeParser(CommandParser):
    def error(self, message):  # noqa: D401 — signature d'argparse
        _safe_error(self, message)


class Command(BaseCommand):
    help = "État (status) ou dépôt (set, secret sur stdin) des identifiants d'un site OAuth."

    # Aucune vérification système : sa sortie éventuelle n'a rien à faire dans
    # un appel scripté, et la commande ne dépend que du modèle Provider.
    requires_system_checks = []

    def create_parser(self, prog_name, subcommand, **kwargs):
        parser = super().create_parser(prog_name, subcommand, **kwargs)
        parser.error = lambda message: _safe_error(parser, message)
        return parser

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest='action', required=True, parser_class=_SafeParser)

        status = sub.add_parser('status', help="Dit si la fiche du site est utilisable.")
        status.add_argument('slug')

        set_ = sub.add_parser(
            'set', help="Enregistre client_id et client_secret (le secret est lu sur stdin).",
        )
        set_.add_argument('slug')
        set_.add_argument('--client-id', required=True, dest='client_id')

    # ── Sorties ───────────────────────────────────────────────────────────────
    def _say(self, message: str) -> None:
        self.stderr.write(message)

    def _usage(self, message: str) -> None:
        self._say(f'provider_credentials : {message}')
        sys.exit(EXIT_USAGE)

    def _report(self, slug: str, provider: Provider | None) -> dict:
        exists = provider is not None
        state = {
            'slug': slug,
            'exists': exists,
            'enabled': bool(exists and provider.enabled),
            'client_id_set': bool(exists and provider.client_id),
            'secret_set': bool(exists and provider.has_client_secret),
            'configured': bool(exists and provider.is_configured),
            'callback_url': _callback_uri(slug),
        }
        self.stdout.write(json.dumps(state, separators=(',', ':')))
        return state

    # ── Commande ──────────────────────────────────────────────────────────────
    def handle(self, *args, **options):
        slug = options['slug']
        if not _SLUG.match(slug):
            self._usage('identifiant de site invalide (lettres, chiffres, « - », « _ »)')

        if options['action'] == 'status':
            self._status(slug)
        else:
            self._set(slug, options['client_id'])

    def _status(self, slug: str) -> None:
        provider = Provider.objects.filter(pk=slug).first()
        state = self._report(slug, provider)
        if not state['exists']:
            self._say(f"Aucune fiche « {slug} » dans oauth-hub.")
            sys.exit(EXIT_ABSENT)
        if not state['configured']:
            manque = [nom for nom, ok in (
                ('client_id', state['client_id_set']),
                ('client_secret', state['secret_set']),
                ('activation', state['enabled']),
            ) if not ok]
            self._say(f"Fiche « {slug} » incomplète : {', '.join(manque)}.")
            sys.exit(EXIT_INCOMPLETE)
        self._say(f"Fiche « {slug} » utilisable.")

    def _set(self, slug: str, client_id: str) -> None:
        client_id = client_id.strip()
        if not client_id:
            self._usage('--client-id vide')

        provider = Provider.objects.filter(pk=slug).first()
        if provider is None:
            self._report(slug, None)
            self._say(f"Aucune fiche « {slug} » dans oauth-hub : rien n'est enregistré.")
            sys.exit(EXIT_ABSENT)

        secret = sys.stdin.readline() if sys.stdin is not None else ''
        secret = secret.rstrip('\r\n')
        if not secret:
            self._usage('client_secret vide (attendu sur la première ligne de stdin)')

        try:
            provider.client_id = client_id
            provider.client_secret = secret
            provider.save(update_fields=['client_id', 'client_secret_encrypted', 'updated_at'])
        except ImproperlyConfigured as exc:
            # Message de crypto.py : il parle de la clé, jamais du secret.
            raise CommandError(str(exc)) from None
        finally:
            del secret

        self._report(slug, provider)
        self._say(f"Identifiants de « {slug} » enregistrés (enabled inchangé).")
