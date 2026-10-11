"""L'aller-retour OAuth : `return_url`, `state`, callback anonyme.

Le callback est le seul endpoint sans jeton. Ce qui y tient lieu
d'authentification est le `state` : ces tests disent ce qu'il laisse passer
(un retour unique, dans les dix minutes, pour le site et la personne qui ont
démarré le flux) et ce qu'il refuse (tout le reste).
"""
from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import requests
from django.utils import timezone

from api.models import Connection, PendingAuthorization
from api.views import _is_safe_return_url

from .base import (
    FRONTEND_URL, ISSUER, MEMBRE, SECRET_SITE, HubTestCase, colonnes_brutes,
    make_connection, make_provider, reponse, token,
)

JETON_AMONT = 'gho_JETON-AMONT-ALICE-0123456789'
BOUCLE = 'http://127.0.0.1:8765/oauth-hub-done'


def query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query, keep_blank_values=True).items()}


class ReturnUrlTests(HubTestCase):
    """`_is_safe_return_url` — domaine du lab et boucle locale, rien d'autre."""

    ACCEPTEES = [
        '',
        'http://127.0.0.1:8765/oauth-hub-done',
        'http://127.0.0.1/',
        'http://localhost:8765/done?x=1',
        'http://[::1]:8765/done',
        'https://lab.example/storage/',
        'https://lab.example:443/oauth-hub/providers?connect=forge',
        'https://LAB.EXAMPLE/storage/',
        'HTTPS://lab.example/',
        'http://lab.example/',
    ]

    REFUSEES = [
        # schémas
        'javascript:alert(1)',
        'javascript://lab.example/%0aalert(1)',
        'data:text/html,<script>alert(1)</script>',
        'file:///etc/passwd',
        'ftp://lab.example/x',
        'vbscript:msgbox(1)',
        'myapp://lab.example/retour',
        # sans schéma : relatif au protocole, relatif, hôte nu
        '//evil.example/x',
        '//lab.example/x',
        '///evil.example',
        '/storage/',
        'lab.example/storage/',
        'evil.example',
        '\\\\evil.example',
        # autres hôtes
        'https://evil.example/',
        'https://evil.example/lab.example',
        'https://evil.example/?next=https://lab.example/',
        'https://evil.example#lab.example',
        'https://evil.example#@lab.example/',
        # hôtes ressemblants
        'https://lab.example.evil.example/',
        'https://evil-lab.example/',
        'https://xlab.example/',
        'https://lab.example.',
        'https://sub.lab.example/',
        'https://lab-example/',
        'https://labxexample/',
        'https://127.0.0.1.evil.example/',
        'https://localhost.evil.example/',
        'http://127.0.0.2:8765/',
        'http://0.0.0.0:8765/',
        'http://localhost.localdomain/',
        # « @ » : la partie avant est un identifiant, pas l'hôte
        'https://lab.example@evil.example/',
        'https://lab.example:443@evil.example/',
        'http://127.0.0.1@evil.example/',
        'http://localhost:8765@evil.example/',
        'https://lab.example%40evil.example/',
        # encodages
        'https://lab.example%2eevil.example/',
        'https://lab.example%2f@evil.example/',
        'https://evil.example%2f%2flab.example/',
        'https://lab%2eexample.evil.example/',
        'https://%6cab.example.evil.example/',
        'https://lab.example。evil.example/',
        'https:/\\evil.example/',
        'https://[::2]/',
    ]

    def test_urls_acceptees(self):
        for url in self.ACCEPTEES:
            with self.subTest(url=url):
                self.assertTrue(_is_safe_return_url(url))

    def test_urls_refusees(self):
        for url in self.REFUSEES:
            with self.subTest(url=url):
                try:
                    verdict = _is_safe_return_url(url)
                except ValueError:
                    verdict = False     # URL que urlparse refuse : pas acceptée
                self.assertFalse(verdict)

    def test_la_liste_d_hotes_vient_du_reglage(self):
        with self.settings(OAUTH_HUB_ALLOWED_RETURN_HOSTS='a.example, B.example ,'):
            self.assertTrue(_is_safe_return_url('https://a.example/x'))
            self.assertTrue(_is_safe_return_url('https://b.example/x'))
            self.assertFalse(_is_safe_return_url('https://lab.example/x'))
            self.assertTrue(_is_safe_return_url('http://127.0.0.1:1/'))
        with self.settings(OAUTH_HUB_ALLOWED_RETURN_HOSTS=''):
            self.assertFalse(_is_safe_return_url('https://lab.example/x'))
            self.assertFalse(_is_safe_return_url('https:///x'))

    def test_authorize_refuse_une_return_url_etrangere(self):
        make_provider()
        tok = token('alice')
        for url in ('https://evil.example/', '//evil.example', 'javascript:alert(1)',
                    'https://lab.example@evil.example/'):
            with self.subTest(url=url):
                resp = self.get('/api/providers/forge/authorize/', tok, {'return_url': url})
                self.assertEqual(resp.status_code, 400)
        self.assertEqual(PendingAuthorization.objects.count(), 0)

    def test_token_ne_relaie_pas_une_return_url_etrangere(self):
        make_provider()
        resp = self.get('/api/providers/forge/token/', token('alice'),
                        {'return_url': 'https://evil.example/'})
        self.assertEqual(resp.status_code, 409)
        self.assertNotIn('evil.example', resp.json()['connect_url'])
        resp = self.get('/api/providers/forge/token/', token('alice'), {'return_url': BOUCLE})
        self.assertEqual(query(resp.json()['connect_url']),
                         {'connect': 'forge', 'return_url': BOUCLE})

    def test_antislash_espace_et_caractere_de_controle_refuses(self):
        """Refusés avant toute analyse : `urlparse` lit `lab.example` comme hôte
        de `https://evil.example\\@lab.example/`, alors qu'un navigateur (règle
        WHATWG : `\\` vaut `/`, tabulations et retours à la ligne retirés) irait
        sur `evil.example`."""
        for url in ('https://evil.example\\@lab.example/',
                    'https://evil.example\\@127.0.0.1/',
                    'https://lab.example\\evil.example/',
                    'https://lab.example/chemin\\x',
                    'http://127.0.0.1:8765/a b',
                    ' https://lab.example/',
                    'https://lab.example/ ',
                    'https://lab.example/\t',
                    'https://lab.example/\nLocation: https://evil.example',
                    'https://lab.example/\r\nSet-Cookie: x=1',
                    'https://evil.example\t@lab.example/',
                    'ht\ntps://lab.example/',
                    'https://lab.example/\x00',
                    'https://lab.example/\x7f',
                    'https://lab.example/\x85',
                    'https://lab.example/\u00a0',
                    'https://lab.example/\u2028'):
            with self.subTest(url=url):
                self.assertFalse(_is_safe_return_url(url))
        make_provider()
        resp = self.get('/api/providers/forge/authorize/', token('alice'),
                        {'return_url': 'https://evil.example\\@lab.example/'})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(PendingAuthorization.objects.count(), 0)

    def test_antislash_neutralise_a_la_redirection(self):
        """Second filet, tenu par Django : même pour un état déjà en base avec
        une telle adresse, le Location émis n'a plus d'antislash."""
        site = make_provider()
        PendingAuthorization.objects.create(
            state='etat-antislash', provider=site, user_email='alice@ssolab.local',
            redirect_uri='https://lab.example/oauth-hub-api/api/callback/forge/',
            return_url='https://evil.example\\@lab.example/',
        )
        resp = self.client.get('/api/callback/forge/', {'state': 'etat-antislash', 'error': 'x'})
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn('\\', resp['Location'])
        self.assertEqual(urlparse(resp['Location']).hostname, 'lab.example')

    def test_status_ne_relaie_pas_une_return_url_etrangere(self):
        """Même contrôle que `TokenView` : un lien du lab ne transporte pas une
        adresse étrangère."""
        make_provider()
        for url in ('https://evil.example/', 'https://evil.example\\@lab.example/',
                    'javascript:alert(1)'):
            with self.subTest(url=url):
                resp = self.get('/api/providers/forge/status/', token('alice'), {'return_url': url})
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(query(resp.json()['connect_url']), {'connect': 'forge'})
        resp = self.get('/api/providers/forge/status/', token('alice'), {'return_url': BOUCLE})
        self.assertEqual(query(resp.json()['connect_url']),
                         {'connect': 'forge', 'return_url': BOUCLE})


class DepartTests(HubTestCase):
    """GET /api/providers/<slug>/authorize/ — création du `state`."""

    def setUp(self) -> None:
        super().setUp()
        self.site = make_provider()
        self.alice = token('alice')

    def test_le_state_est_lie_a_l_appelant(self):
        resp = self.get('/api/providers/forge/authorize/', self.alice, {'return_url': BOUCLE})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['expires_in'], 600)
        params = query(resp.json()['authorization_url'])
        self.assertTrue(resp.json()['authorization_url'].startswith(
            'https://forge.example/oauth/authorize?'))
        attente = PendingAuthorization.objects.get()
        self.assertEqual(params['state'], attente.state)
        self.assertEqual(attente.user_email, 'alice@ssolab.local')
        self.assertEqual(attente.provider_id, 'forge')
        self.assertEqual(attente.return_url, BOUCLE)
        self.assertEqual(params['redirect_uri'],
                         'https://lab.example/oauth-hub-api/api/callback/forge/')
        self.assertEqual(attente.redirect_uri, params['redirect_uri'])
        self.assertEqual(params['client_id'], 'cid-forge')
        self.assertEqual(params['response_type'], 'code')
        self.assertEqual(params['scope'], 'read:user repo')
        # Le secret du site ne part jamais vers le navigateur.
        self.assertNotIn(SECRET_SITE, resp.content.decode())
        self.assertNotIn('client_secret', params)

    def test_le_state_est_imprevisible_et_unique(self):
        etats = {
            query(self.get('/api/providers/forge/authorize/', self.alice)
                  .json()['authorization_url'])['state']
            for _ in range(20)
        }
        self.assertEqual(len(etats), 20)
        self.assertTrue(all(len(e) >= 43 for e in etats))   # 32 octets en base64url

    def test_l_identite_ne_vient_pas_de_la_requete(self):
        self.get('/api/providers/forge/authorize/', self.alice,
                 {'user_email': 'bob@ssolab.local', 'email': 'bob@ssolab.local'})
        self.assertEqual(PendingAuthorization.objects.get().user_email, 'alice@ssolab.local')

    def test_pkce_s256_quand_le_site_le_supporte(self):
        make_provider('pkce', use_pkce=True)
        params = query(self.get('/api/providers/pkce/authorize/', self.alice)
                       .json()['authorization_url'])
        attente = PendingAuthorization.objects.get(provider_id='pkce')
        self.assertGreaterEqual(len(attente.code_verifier), 43)
        attendu = base64.urlsafe_b64encode(
            hashlib.sha256(attente.code_verifier.encode()).digest()).decode().rstrip('=')
        self.assertEqual(params['code_challenge'], attendu)
        self.assertEqual(params['code_challenge_method'], 'S256')
        # Le vérificateur reste côté serveur.
        self.assertNotIn(attente.code_verifier, str(params))

        sans = query(self.get('/api/providers/forge/authorize/', self.alice)
                     .json()['authorization_url'])
        self.assertNotIn('code_challenge', sans)
        self.assertEqual(PendingAuthorization.objects.get(provider_id='forge').code_verifier, '')

    def test_portees_et_separateur(self):
        make_provider('virgule', scope_separator=',')
        params = query(self.get('/api/providers/virgule/authorize/', self.alice,
                                {'scopes': 'a b'}).json()['authorization_url'])
        self.assertEqual(params['scope'], 'a,b')

    def test_site_inconnu(self):
        self.assertEqual(self.get('/api/providers/absent/authorize/', self.alice).status_code, 404)

    def test_les_etats_perimes_sont_purges_au_depart(self):
        PendingAuthorization.objects.create(
            state='vieux', provider=self.site, user_email='bob@ssolab.local',
            redirect_uri='https://x.example/')
        PendingAuthorization.objects.create(
            state='recent', provider=self.site, user_email='bob@ssolab.local',
            redirect_uri='https://x.example/')
        PendingAuthorization.objects.filter(pk='vieux').update(
            created_at=timezone.now() - timedelta(minutes=11))
        self.get('/api/providers/forge/authorize/', self.alice)
        restants = set(PendingAuthorization.objects.values_list('state', flat=True))
        self.assertNotIn('vieux', restants)
        self.assertIn('recent', restants)
        self.assertEqual(len(restants), 2)


class RetourTests(HubTestCase):
    """GET /api/callback/<slug>/ — anonyme, protégé par le `state`."""

    def setUp(self) -> None:
        super().setUp()
        self.site = make_provider(account_url='https://forge.example/api/user')
        self.alice = token('alice')

    def depart(self, tok=None, slug='forge', **params) -> str:
        resp = self.get(f'/api/providers/{slug}/authorize/', tok or self.alice, params)
        self.assertEqual(resp.status_code, 200, resp.content)
        return query(resp.json()['authorization_url'])['state']

    def retour(self, slug='forge', **params):
        """Le navigateur revient du site : aucun jeton Keycloak."""
        return self.client.get(f'/api/callback/{slug}/', params)

    def fournisseur_ok(self, **extra):
        self.simule_jeton({'access_token': JETON_AMONT, 'token_type': 'bearer',
                           'scope': 'read:user', **extra})
        self.http_get.side_effect = None
        self.http_get.return_value = reponse(200, {'login': 'alice-forge'})

    def assertErreur(self, resp, code: str, base: str = f'{FRONTEND_URL}/providers'):
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp['Location'].startswith(base + '?'), resp['Location'])
        self.assertEqual(query(resp['Location'])['oauth_error_code'], code)

    # ── Le chemin nominal ─────────────────────────────────────────────────────
    def test_retour_valide_relie_le_compte_de_celui_qui_a_demarre(self):
        state = self.depart(return_url=BOUCLE)
        self.fournisseur_ok()

        resp = self.retour(state=state, code='code-du-site')

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp['Location'].startswith(BOUCLE + '?'))
        # L'échange : une seule requête, vers l'URL du site, avec le secret et
        # l'URI de rappel rejouée à l'identique.
        self.http_post.assert_called_once()
        (url,), kwargs = self.http_post.call_args
        self.assertEqual(url, 'https://forge.example/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid-forge', 'client_secret': SECRET_SITE,
            'code': 'code-du-site', 'grant_type': 'authorization_code',
            'redirect_uri': 'https://lab.example/oauth-hub-api/api/callback/forge/',
        })
        self.assertTrue(kwargs['timeout'])
        # La connexion appartient à alice, jeton chiffré.
        connexion = Connection.objects.get()
        self.assertEqual(connexion.user_email, 'alice@ssolab.local')
        self.assertEqual(connexion.provider_id, 'forge')
        self.assertEqual(connexion.access_token, JETON_AMONT)
        self.assertEqual(connexion.account_label, 'alice-forge')
        self.assertIsNone(connexion.expires_at)
        self.assertNotIn(JETON_AMONT, colonnes_brutes('connections'))

    def test_le_retour_ne_porte_jamais_le_jeton(self):
        state = self.depart(return_url=BOUCLE)
        self.fournisseur_ok(refresh_token='RENOUV-AMONT-ALICE', expires_in=3600)
        resp = self.retour(state=state, code='c')
        self.assertNotIn(JETON_AMONT, resp['Location'])
        self.assertNotIn('RENOUV-AMONT-ALICE', resp['Location'])
        self.assertNotIn(SECRET_SITE, resp['Location'])
        params = query(resp['Location'])
        self.assertEqual(params['connected'], 'forge')
        self.assertEqual(params['provider'], 'forge')
        self.assertEqual(params['token_url'],
                         'https://lab.example/oauth-hub-api/api/providers/forge/token/')
        self.assertEqual(params['status_url'],
                         'https://lab.example/oauth-hub-api/api/providers/forge/status/')
        self.assertEqual(params['issuer'], ISSUER)
        self.assertEqual(params['auto_renew'], 'true')
        self.assertEqual(params['account'], 'alice-forge')
        self.assertIn('expires_at', params)
        self.assertNotIn('access_token', params)

    def test_sans_return_url_retour_sur_l_interface(self):
        state = self.depart()
        self.fournisseur_ok()
        resp = self.retour(state=state, code='c')
        self.assertTrue(resp['Location'].startswith(f'{FRONTEND_URL}/providers?'))
        self.assertEqual(query(resp['Location'])['auto_renew'], 'false')

    def test_pkce_le_verificateur_part_a_l_echange(self):
        make_provider('pkce', use_pkce=True)
        state = self.depart(slug='pkce')
        verifier = PendingAuthorization.objects.get(pk=state).code_verifier
        self.fournisseur_ok()
        self.retour('pkce', state=state, code='c')
        self.assertEqual(self.http_post.call_args.kwargs['data']['code_verifier'], verifier)

    # ── Usage unique ──────────────────────────────────────────────────────────
    def test_un_state_ne_sert_qu_une_fois(self):
        state = self.depart()
        self.fournisseur_ok()
        self.assertEqual(self.retour(state=state, code='c1').status_code, 302)
        self.assertFalse(PendingAuthorization.objects.filter(pk=state).exists())

        # Rejeu, avec un code qui donnerait un autre jeton.
        self.simule_jeton({'access_token': 'JETON-DU-REJOUEUR'})
        self.assertErreur(self.retour(state=state, code='c2'), 'unknown_state')
        self.assertEqual(self.http_post.call_count, 1)
        self.assertEqual(Connection.objects.get().access_token, JETON_AMONT)

    def test_state_consomme_meme_si_l_echange_echoue(self):
        state = self.depart()
        self.simule_jeton({'error': 'bad_verification_code'})
        with self.assertLogs('api.views', level='WARNING'):
            self.assertErreur(self.retour(state=state, code='c'), 'exchange_failed')
        self.fournisseur_ok()
        self.assertErreur(self.retour(state=state, code='c'), 'unknown_state')
        self.assertEqual(Connection.objects.count(), 0)

    # ── Ce que le callback refuse ─────────────────────────────────────────────
    def test_state_absent_inconnu_ou_devine(self):
        self.depart()
        self.fournisseur_ok()
        for params in ({}, {'code': 'c'}, {'state': '', 'code': 'c'},
                       {'state': 'devine', 'code': 'c'}, {'state': 'A' * 43, 'code': 'c'}):
            with self.subTest(params=params):
                resp = self.retour(**params)
                self.assertErreur(resp, 'unknown_state')
                # Rien sur le flux en cours n'est confirmé à un tiers.
                self.assertNotIn('provider', query(resp['Location']))
        self.http_post.assert_not_called()
        self.assertEqual(Connection.objects.count(), 0)
        self.assertEqual(PendingAuthorization.objects.count(), 1)

    def test_state_expire(self):
        state = self.depart(return_url=BOUCLE)
        PendingAuthorization.objects.filter(pk=state).update(
            created_at=timezone.now() - timedelta(minutes=10, seconds=1))
        self.fournisseur_ok()
        self.assertErreur(self.retour(state=state, code='c'), 'expired_state', BOUCLE)
        self.http_post.assert_not_called()
        self.assertEqual(Connection.objects.count(), 0)
        self.assertFalse(PendingAuthorization.objects.filter(pk=state).exists())

    def test_state_encore_valide_juste_avant_dix_minutes(self):
        state = self.depart()
        PendingAuthorization.objects.filter(pk=state).update(
            created_at=timezone.now() - timedelta(minutes=9, seconds=50))
        self.fournisseur_ok()
        self.assertIn('connected', query(self.retour(state=state, code='c')['Location']))

    def test_state_d_un_site_rejoue_sur_un_autre(self):
        make_provider('autre')
        state = self.depart()                       # démarré pour « forge »
        self.fournisseur_ok()
        self.assertErreur(self.retour('autre', state=state, code='c'), 'provider_mismatch')
        self.http_post.assert_not_called()
        self.assertEqual(Connection.objects.count(), 0)
        self.assertFalse(PendingAuthorization.objects.filter(pk=state).exists())

    def test_refus_de_l_utilisateur_ou_code_absent(self):
        self.fournisseur_ok()
        state = self.depart(return_url=BOUCLE)
        resp = self.retour(state=state, error='access_denied', error_description='Refusé')
        self.assertErreur(resp, 'provider_refused', BOUCLE)
        self.assertEqual(query(resp['Location'])['oauth_error'], 'Refusé')
        self.assertEqual(query(resp['Location'])['provider'], 'forge')

        state = self.depart()
        self.assertErreur(self.retour(state=state), 'no_code')
        self.http_post.assert_not_called()
        self.assertEqual(Connection.objects.count(), 0)

    def test_echecs_de_l_echange(self):
        """Erreur en HTTP 200 (GitHub), HTTP 4xx, corps illisible, site
        injoignable, réponse sans jeton : jamais de connexion créée."""
        cas = {
            'erreur_en_200': dict(return_value=reponse(200, {'error': 'bad_code',
                                                             'error_description': 'Code périmé'})),
            'http_400': dict(return_value=reponse(400, {'error': 'invalid_client'})),
            'http_500_html': dict(return_value=reponse(500, None, '<html>panne</html>')),
            'sans_jeton': dict(return_value=reponse(200, {'token_type': 'bearer'})),
            'injoignable': dict(side_effect=requests.ConnectionError('réseau coupé')),
            'delai': dict(side_effect=requests.Timeout('trop long')),
        }
        for nom, comportement in cas.items():
            with self.subTest(cas=nom):
                state = self.depart()
                self.http_post.reset_mock(return_value=True, side_effect=True)
                self.http_post.configure_mock(**comportement)
                with self.assertLogs('api.views', level='WARNING'):
                    resp = self.retour(state=state, code='c')
                self.assertErreur(resp, 'exchange_failed')
                self.assertEqual(Connection.objects.count(), 0)

    # ── Qui reçoit le jeton ───────────────────────────────────────────────────
    def test_le_jeton_va_a_celui_qui_a_demarre_pas_a_celui_qui_revient(self):
        """Le retour n'a aucune identité : rien dans la requête de callback ne
        peut désigner un autre compte que celui lié au `state`."""
        state_alice = self.depart(self.alice)
        state_bob = self.depart(token('bob'))
        self.fournisseur_ok()
        self.client.get('/api/callback/forge/', {
            'state': state_bob, 'code': 'c', 'user_email': 'alice@ssolab.local',
            'email': 'alice@ssolab.local',
        }, HTTP_AUTHORIZATION=f'Bearer {self.alice}')
        self.assertEqual(list(Connection.objects.values_list('user_email', flat=True)),
                         ['bob@ssolab.local'])
        self.assertTrue(PendingAuthorization.objects.filter(pk=state_alice).exists())

    def test_reconnexion_met_a_jour_sans_perdre_le_renouvellement(self):
        """Un site qui ne renvoie pas de refresh_token la seconde fois (Google)
        ne doit pas effacer celui déjà détenu."""
        make_connection(self.site, 'alice', 'ancien', 'RENOUV-INITIAL', account_label='alice-forge')
        state = self.depart()
        self.fournisseur_ok()
        self.http_get.return_value = reponse(500, None)      # profil en panne
        self.retour(state=state, code='c')
        connexion = Connection.objects.get()
        self.assertEqual(connexion.access_token, JETON_AMONT)
        self.assertEqual(connexion.refresh_token, 'RENOUV-INITIAL')
        self.assertEqual(connexion.account_label, 'alice-forge')

    def test_profil_injoignable_ne_fait_pas_echouer_la_connexion(self):
        state = self.depart()
        self.fournisseur_ok()
        self.http_get.side_effect = requests.ConnectionError('profil injoignable')
        resp = self.retour(state=state, code='c')
        self.assertEqual(query(resp['Location'])['connected'], 'forge')
        self.assertEqual(Connection.objects.get().account_label, '')

    def test_expiration_annoncee_par_le_site(self):
        state = self.depart()
        self.fournisseur_ok(expires_in=7200)
        avant = timezone.now()
        self.retour(state=state, code='c')
        echeance = Connection.objects.get().expires_at
        self.assertAlmostEqual((echeance - avant).total_seconds(), 7200, delta=30)

        state = self.depart()
        self.fournisseur_ok(expires_in='bientôt')          # hors norme : non expirant
        self.retour(state=state, code='c')
        self.assertIsNone(Connection.objects.get().expires_at)
