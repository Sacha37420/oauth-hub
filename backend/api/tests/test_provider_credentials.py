"""Commande `provider_credentials` (interface I1 du chantier « nuit-auto »).

Jouée comme `docker exec … python manage.py provider_credentials …` la joue :
par `run_from_argv`, donc avec le vrai analyseur d'arguments et les vrais codes
de sortie (un `call_command` transformerait toute erreur en CommandError).
Seule entorse : `connections.close_all()`, que `run_from_argv` appelle en sortie,
est neutralisé — il casserait la transaction du test.

Propriétés tenues :
  • stdout = exactement une ligne JSON, et rien d'autre ;
  • codes 0 / 2 / 3 / 4 exactement comme le contrat ;
  • le secret n'est lu que sur stdin et ne ressort sur aucune sortie, même
    quand on le passe par erreur en argument ;
  • ce qui est stocké se déchiffre en la valeur donnée ; `enabled` n'est pas touché.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from api.management.commands.provider_credentials import Command
from api.models import Provider

from .base import BACKEND_URL, HubTestCase, colonnes_brutes, make_provider

SECRET = 'gh-secret-NE-DOIT-JAMAIS-SORTIR-7f3a9c'
CLES = ['slug', 'exists', 'enabled', 'client_id_set', 'secret_set', 'configured', 'callback_url']
BACKEND_DIR = Path(__file__).resolve().parents[2]


class ProviderCredentialsTests(HubTestCase):

    # ── Lanceur ───────────────────────────────────────────────────────────────
    def run_cmd(self, *argv: str, stdin: str = ''):
        """Rend (code, stdout, stderr). Le Command est créé APRÈS la redirection :
        OutputWrapper capture sys.stdout/sys.stderr à sa construction."""
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(sys, 'stdin', io.StringIO(stdin)), \
                mock.patch('django.core.management.base.connections.close_all'):
            try:
                Command().run_from_argv(['manage.py', 'provider_credentials', *argv])
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    def ligne_json(self, stdout: str) -> dict:
        lignes = stdout.splitlines()
        self.assertEqual(len(lignes), 1, f'stdout doit être une seule ligne : {stdout!r}')
        data = json.loads(lignes[0])
        self.assertEqual(list(data), CLES)
        return data

    def assertSansSecret(self, *sorties: str) -> None:
        for sortie in sorties:
            self.assertNotIn(SECRET, sortie)

    # ── status ────────────────────────────────────────────────────────────────
    def test_status_fiche_configuree_code_0(self):
        make_provider('github', secret=SECRET)
        code, out, err = self.run_cmd('status', 'github')
        self.assertEqual(code, 0, err)
        self.assertEqual(self.ligne_json(out), {
            'slug': 'github', 'exists': True, 'enabled': True, 'client_id_set': True,
            'secret_set': True, 'configured': True,
            'callback_url': f'{BACKEND_URL}/api/callback/github/',
        })
        self.assertSansSecret(out, err)

    def test_status_callback_vient_de_views(self):
        make_provider('github')
        with mock.patch('api.management.commands.provider_credentials._callback_uri',
                        return_value='https://ailleurs.example/cb/') as cb:
            _, out, _ = self.run_cmd('status', 'github')
        cb.assert_called_with('github')
        self.assertEqual(self.ligne_json(out)['callback_url'], 'https://ailleurs.example/cb/')

    def test_status_fiche_absente_code_4(self):
        code, out, err = self.run_cmd('status', 'github')
        self.assertEqual(code, 4)
        self.assertEqual(self.ligne_json(out), {
            'slug': 'github', 'exists': False, 'enabled': False, 'client_id_set': False,
            'secret_set': False, 'configured': False,
            'callback_url': f'{BACKEND_URL}/api/callback/github/',
        })
        self.assertTrue(err.strip())

    def test_status_sans_secret_code_3(self):
        make_provider('github', secret='')
        code, out, _ = self.run_cmd('status', 'github')
        self.assertEqual(code, 3)
        data = self.ligne_json(out)
        self.assertEqual((data['exists'], data['client_id_set'], data['secret_set'],
                          data['configured']), (True, True, False, False))

    def test_status_sans_client_id_code_3(self):
        make_provider('github', client_id='')
        code, out, _ = self.run_cmd('status', 'github')
        self.assertEqual(code, 3)
        data = self.ligne_json(out)
        self.assertEqual((data['client_id_set'], data['secret_set'], data['configured']),
                         (False, True, False))

    def test_status_fiche_desactivee_code_3(self):
        make_provider('github', secret=SECRET, enabled=False)
        code, out, err = self.run_cmd('status', 'github')
        self.assertEqual(code, 3)
        data = self.ligne_json(out)
        self.assertEqual((data['enabled'], data['client_id_set'], data['secret_set'],
                          data['configured']), (False, True, True, False))
        self.assertSansSecret(out, err)

    def test_status_seme_par_la_migration_est_incomplet(self):
        """Le défaut d'install.sh : la ligne `github` existe toujours après
        migration, mais sans identifiants — status doit le dire (3)."""
        Provider.objects.create(
            slug='github', display_name='GitHub',
            authorization_url='https://github.com/login/oauth/authorize',
            token_url='https://github.com/login/oauth/access_token', client_id='',
        )
        code, _, _ = self.run_cmd('status', 'github')
        self.assertEqual(code, 3)

    # ── set ───────────────────────────────────────────────────────────────────
    def test_set_enregistre_et_chiffre(self):
        make_provider('github', secret='', client_id='')
        code, out, err = self.run_cmd('set', 'github', '--client-id', 'Iv1.abc', stdin=SECRET + '\n')
        self.assertEqual(code, 0, err)
        data = self.ligne_json(out)
        self.assertEqual((data['client_id_set'], data['secret_set'], data['configured']),
                         (True, True, True))
        provider = Provider.objects.get(pk='github')
        self.assertEqual(provider.client_id, 'Iv1.abc')
        self.assertEqual(provider.client_secret, SECRET)
        self.assertNotIn(SECRET, colonnes_brutes('providers'))
        self.assertSansSecret(out, err)

    def test_set_retire_seulement_la_fin_de_ligne(self):
        make_provider('github', secret='')
        self.run_cmd('set', 'github', '--client-id', 'x', stdin=f' {SECRET} \r\nligne2\n')
        self.assertEqual(Provider.objects.get(pk='github').client_secret, f' {SECRET} ')

    def test_set_sans_fin_de_ligne(self):
        make_provider('github', secret='')
        code, _, _ = self.run_cmd('set', 'github', '--client-id', 'x', stdin=SECRET)
        self.assertEqual(code, 0)
        self.assertEqual(Provider.objects.get(pk='github').client_secret, SECRET)

    def test_set_ne_touche_pas_enabled(self):
        make_provider('github', secret='', enabled=False)
        code, out, _ = self.run_cmd('set', 'github', '--client-id', 'x', stdin=SECRET + '\n')
        self.assertEqual(code, 0)
        self.assertFalse(Provider.objects.get(pk='github').enabled)
        self.assertEqual((self.ligne_json(out)['enabled'], self.ligne_json(out)['configured']),
                         (False, False))

    def test_set_remplace_un_secret_existant(self):
        make_provider('github', secret='ancien-secret')
        self.run_cmd('set', 'github', '--client-id', 'nouveau', stdin=SECRET + '\n')
        provider = Provider.objects.get(pk='github')
        self.assertEqual((provider.client_id, provider.client_secret), ('nouveau', SECRET))

    def test_set_fiche_absente_code_4_rien_cree(self):
        code, out, err = self.run_cmd('set', 'github', '--client-id', 'x', stdin=SECRET + '\n')
        self.assertEqual(code, 4)
        self.assertFalse(self.ligne_json(out)['exists'])
        self.assertFalse(Provider.objects.exists())
        self.assertSansSecret(out, err)

    def test_set_secret_vide_code_2_rien_ecrit(self):
        make_provider('github', secret='ancien-secret', client_id='ancien')
        for stdin in ('', '\n', '\r\n'):
            with self.subTest(stdin=stdin):
                code, out, err = self.run_cmd('set', 'github', '--client-id', 'x', stdin=stdin)
                self.assertEqual(code, 2)
                self.assertEqual(out, '')
                self.assertTrue(err.strip())
        provider = Provider.objects.get(pk='github')
        self.assertEqual((provider.client_id, provider.client_secret), ('ancien', 'ancien-secret'))

    def test_set_client_id_vide_code_2(self):
        make_provider('github', secret='')
        code, out, _ = self.run_cmd('set', 'github', '--client-id', '  ', stdin=SECRET + '\n')
        self.assertEqual((code, out), (2, ''))
        self.assertFalse(Provider.objects.get(pk='github').has_client_secret)

    # ── usage ─────────────────────────────────────────────────────────────────
    def test_usage_code_2(self):
        make_provider('github')
        for argv in ([], ['inconnue', 'github'], ['status'], ['set', 'github'],
                     ['status', 'git hub'], ['status', '../github']):
            with self.subTest(argv=argv):
                code, out, err = self.run_cmd(*argv, stdin=SECRET + '\n')
                self.assertEqual(code, 2, err)
                self.assertEqual(out, '')
                self.assertTrue(err.strip())

    def test_secret_passe_en_argument_refuse_et_jamais_recopie(self):
        """argparse recopie l'argument fautif dans son message : la commande ne
        doit pas, sans quoi une erreur de saisie publierait le secret."""
        make_provider('github', secret='')
        for argv in (['set', 'github', '--client-id', 'x', SECRET],
                     ['set', 'github', '--client-id', 'x', '--client-secret', SECRET],
                     ['set', 'github', '--client-id', 'x', f'--client-secret={SECRET}'],
                     ['status', 'github', SECRET],
                     [SECRET]):
            with self.subTest(argv=argv):
                code, out, err = self.run_cmd(*argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, '')
                self.assertSansSecret(out, err)
        self.assertFalse(Provider.objects.get(pk='github').has_client_secret)

    def test_cle_de_chiffrement_absente_erreur_sans_secret(self):
        make_provider('github', secret='')
        with self.settings(OAUTH_HUB_ENCRYPTION_KEY=''):
            code, out, err = self.run_cmd('set', 'github', '--client-id', 'x', stdin=SECRET + '\n')
        self.assertNotEqual(code, 0)
        self.assertEqual(out, '')
        self.assertIn('OAUTH_HUB_ENCRYPTION_KEY', err)
        self.assertSansSecret(out, err)
        self.assertFalse(Provider.objects.get(pk='github').has_client_secret)

    def test_vrai_processus_manage_py(self):
        """Le vrai `python manage.py` (pas de base touchée : refus à l'analyse)."""
        for argv in (['inconnue', 'github'], ['set', 'github', '--client-id', 'x', SECRET]):
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, 'manage.py', 'provider_credentials', *argv],
                    cwd=BACKEND_DIR, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                )
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, '')
                self.assertSansSecret(proc.stdout, proc.stderr)
