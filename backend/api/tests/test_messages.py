"""Ce qui sort d'oauth-hub en cas d'erreur, et ce qu'il journalise.

- une `return_url` que `urlparse` ne sait pas lire est refusée, jamais une 500 ;
- une erreur réseau vers le site ne relaie pas l'URL demandée (le texte d'une
  exception `requests` la porte, paramètres compris) ;
- les remises de jeton sont journalisées hors des tests (niveau INFO actif).
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlparse

import requests

from api.models import PendingAuthorization
from api.views import _is_safe_return_url

from .base import FRONTEND_URL, HubTestCase, make_provider, token

ILLISIBLES = ['http://[::1', 'https://[lab.example]/', 'http://evil＃@lab.example/']


def query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


class ReturnUrlIllisibleTests(HubTestCase):
    def test_refusee_sans_exception(self):
        for url in ILLISIBLES:
            with self.subTest(url=url):
                self.assertFalse(_is_safe_return_url(url))

    def test_authorize_repond_400(self):
        make_provider()
        for url in ILLISIBLES:
            with self.subTest(url=url):
                resp = self.get('/api/providers/forge/authorize/', token('alice'), {'return_url': url})
                self.assertEqual(resp.status_code, 400)
        self.assertEqual(PendingAuthorization.objects.count(), 0)


class ErreurReseauTests(HubTestCase):
    def test_l_erreur_reseau_ne_relaie_pas_l_url_du_site(self):
        make_provider('cle', token_url='https://cle.example/oauth/token?api_key=SECRET-URL')
        resp = self.get('/api/providers/cle/authorize/', token('alice'))
        self.assertEqual(resp.status_code, 200, resp.content)
        state = query(resp.json()['authorization_url'])['state']
        self.http_post.side_effect = requests.ConnectionError(
            "HTTPSConnectionPool: Max retries exceeded with url: /oauth/token?api_key=SECRET-URL")

        with self.assertLogs('api.views', level='WARNING') as journal:
            resp = self.client.get('/api/callback/cle/', {'state': state, 'code': 'c'})

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp['Location'].startswith(f'{FRONTEND_URL}/providers?'))
        self.assertEqual(query(resp['Location'])['oauth_error_code'], 'exchange_failed')
        self.assertNotIn('SECRET-URL', resp['Location'])
        self.assertNotIn('SECRET-URL', '\n'.join(journal.output))


class JournalTests(HubTestCase):
    def test_la_journalisation_des_remises_est_active_hors_test(self):
        self.assertTrue(logging.getLogger('api.views').isEnabledFor(logging.INFO))
