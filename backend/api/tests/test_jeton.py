"""La remise du jeton amont — l'endpoint pour lequel l'app existe.

Tenu ici : un jeton amont ne sort que par `GET /api/providers/<slug>/token/`,
seulement pour la personne qui l'a relié, et chaque remise est journalisée
(quelle app, pour qui, quel site) sans que le jeton lui-même soit écrit.
"""
from __future__ import annotations

from datetime import timedelta

import requests
from django.utils import timezone

from api.models import Connection, TrustedClient

from .base import (
    DEV, FRONTEND_URL, MEMBRE, SECRET_SITE, HubTestCase, colonnes_brutes,
    make_connection, make_provider, reponse, token,
)

JETON_ALICE = 'gho_JETON-AMONT-ALICE-0123456789'
RENOUV_ALICE = 'ghr_RENOUV-AMONT-ALICE-0123456789'
JETON_BOB = 'gho_JETON-AMONT-BOB-9876543210'


class RemiseTests(HubTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.site = make_provider()
        self.alice = token('alice')
        self.bob = token('bob')
        self.connexion = make_connection(self.site, 'alice', JETON_ALICE, scope='read:user',
                                         account_label='alice-forge')

    def test_alice_recoit_son_jeton(self):
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {
            'access_token': JETON_ALICE, 'token_type': 'bearer',
            'scope': 'read:user', 'expires_at': None,
        })
        self.http_post.assert_not_called()

    def test_bob_ne_recoit_pas_le_jeton_d_alice(self):
        """Ni directement, ni en désignant alice dans la requête."""
        for params in ({}, {'user_email': 'alice@ssolab.local'}, {'email': 'alice@ssolab.local'},
                       {'user': 'alice'}):
            with self.subTest(params=params):
                resp = self.get('/api/providers/forge/token/', self.bob, params)
                self.assertEqual(resp.status_code, 409)
                self.assertNotIn(JETON_ALICE, resp.content.decode())
                self.assertEqual(resp.json()['provider'], 'forge')
                self.assertEqual(resp.json()['connect_url'],
                                 f'{FRONTEND_URL}/providers?connect=forge')

    def test_chacun_le_sien(self):
        make_connection(self.site, 'bob', JETON_BOB)
        self.assertEqual(self.get('/api/providers/forge/token/', self.alice).json()['access_token'],
                         JETON_ALICE)
        self.assertEqual(self.get('/api/providers/forge/token/', self.bob).json()['access_token'],
                         JETON_BOB)

    def test_un_homonyme_d_un_autre_domaine_n_est_pas_alice(self):
        resp = self.get('/api/providers/forge/token/',
                        token('alice', email='alice@ailleurs.example'))
        self.assertEqual(resp.status_code, 409)

    def test_la_connexion_d_un_site_ne_vaut_pas_pour_un_autre(self):
        make_provider('autre')
        self.assertEqual(self.get('/api/providers/autre/token/', self.alice).status_code, 409)
        self.assertEqual(self.get('/api/providers/absent/token/', self.alice).status_code, 404)

    def test_chaque_remise_est_journalisee_sans_le_jeton(self):
        TrustedClient.objects.create(client_id='storage-analysis')
        via_app = token('alice', MEMBRE, azp='storage-analysis')
        with self.assertLogs('api.views', level='INFO') as journal:
            self.assertEqual(self.get('/api/providers/forge/token/', via_app).status_code, 200)
        self.assertEqual(len(journal.records), 1)
        ligne = journal.output[0]
        self.assertIn("'forge'", ligne)
        self.assertIn("'storage-analysis'", ligne)       # QUELLE app
        self.assertIn('alice@ssolab.local', ligne)       # pour QUI
        self.assertNotIn(JETON_ALICE, ligne)

    def test_un_refus_n_est_pas_journalise_comme_une_remise(self):
        with self.assertNoLogs('api.views', level='INFO'):
            self.get('/api/providers/forge/token/', self.bob)

    def test_une_app_non_autorisee_ne_recoit_rien(self):
        for azp in ('admin-cli', 'app-inconnue'):
            with self.subTest(azp=azp):
                resp = self.get('/api/providers/forge/token/', token('alice', DEV, azp=azp))
                self.assertRefuse(resp, 'client non autorisé')
                self.assertNotIn(JETON_ALICE, resp.content.decode())

    def test_app_revoquee_ne_recoit_plus_le_jeton(self):
        fiche = TrustedClient.objects.create(client_id='storage-analysis')
        via_app = token('alice', MEMBRE, azp='storage-analysis')
        self.assertEqual(self.get('/api/providers/forge/token/', via_app).status_code, 200)
        fiche.delete()
        self.assertRefuse(self.get('/api/providers/forge/token/', via_app))

    def test_un_site_desactive_ne_remet_plus_de_jeton(self):
        """« Site actif » décoché : coupure immédiate pour tout le lab, sans
        perdre les connexions — rien n'est remis, rien n'est renouvelé, aucun
        aller-retour ne démarre. Le statut continue de décrire le site."""
        self.connexion.refresh_token = RENOUV_ALICE
        self.connexion.expires_at = timezone.now() - timedelta(minutes=5)
        self.connexion.save()
        self.site.enabled = False
        self.site.save()

        with self.assertNoLogs('api.views', level='INFO'):
            resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.status_code, 403)
        self.assertIn('désactivé', resp.json()['detail'])
        self.assertNotIn(JETON_ALICE, resp.content.decode())
        self.http_post.assert_not_called()                 # pas de renouvellement non plus
        # Même refus pour qui n'a rien relié : pas de 409 l'invitant à relier un site coupé.
        self.assertEqual(self.get('/api/providers/forge/token/', self.bob).status_code, 403)
        self.assertEqual(self.get('/api/providers/forge/authorize/', self.alice).status_code, 400)

        etat = self.get('/api/providers/forge/status/', self.alice)
        self.assertEqual(etat.status_code, 200)
        self.assertIs(etat.json()['configured'], False)

        # Réactivé : la connexion est toujours là.
        self.connexion.expires_at = None
        self.connexion.save()
        self.site.enabled = True
        self.site.save()
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.json()['access_token'], JETON_ALICE)

    # ── Aucun autre endpoint ne rend un jeton ─────────────────────────────────
    def test_aucune_autre_lecture_ne_rend_un_jeton(self):
        self.connexion.refresh_token = RENOUV_ALICE
        self.connexion.save()
        chiffres = Connection.objects.values_list(
            'access_token_encrypted', 'refresh_token_encrypted').get()
        for path in ('/api/connections/', '/api/providers/forge/status/', '/api/providers/',
                     '/api/providers/forge/', '/api/me/', '/api/trusted-clients/'):
            with self.subTest(path=path):
                resp = self.get(path, token('alice', DEV))
                self.assertEqual(resp.status_code, 200)
                corps = resp.content.decode()
                for interdit in (JETON_ALICE, RENOUV_ALICE, SECRET_SITE, *chiffres):
                    self.assertNotIn(interdit, corps)
        # Le jeton de renouvellement ne sort pas non plus par l'endpoint de remise.
        self.assertNotIn(RENOUV_ALICE,
                         self.get('/api/providers/forge/token/', self.alice).content.decode())

    # ── Mes connexions ────────────────────────────────────────────────────────
    def test_je_ne_vois_que_mes_connexions(self):
        make_connection(self.site, 'bob', JETON_BOB)
        vues = self.get('/api/connections/', self.alice).json()
        self.assertEqual([(c['provider'], c['account_label']) for c in vues],
                         [('forge', 'alice-forge')])
        self.assertEqual(self.get('/api/connections/', token('carole')).json(), [])

    def test_je_ne_delie_que_ma_connexion(self):
        resp = self.call('delete', '/api/connections/forge/', self.bob)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(Connection.objects.count(), 1)

        make_connection(self.site, 'bob', JETON_BOB)
        self.assertEqual(self.call('delete', '/api/connections/forge/', self.bob).status_code, 204)
        self.assertEqual(list(Connection.objects.values_list('user_email', flat=True)),
                         ['alice@ssolab.local'])
        self.assertEqual(self.get('/api/providers/forge/token/', self.bob).status_code, 409)

    def test_etat_sans_faire_transiter_le_jeton(self):
        relie = self.get('/api/providers/forge/status/', self.alice).json()
        self.assertEqual((relie['connected'], relie['configured'], relie['account_label']),
                         (True, True, 'alice-forge'))
        non_relie = self.get('/api/providers/forge/status/', self.bob).json()
        self.assertEqual((non_relie['connected'], non_relie['account_label'], non_relie['scope']),
                         (False, '', ''))


class RenouvellementTests(HubTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.site = make_provider()
        self.alice = token('alice')

    def expire_dans(self, secondes: int, refresh: str = RENOUV_ALICE) -> Connection:
        return make_connection(self.site, 'alice', JETON_ALICE, refresh,
                               expires_at=timezone.now() + timedelta(seconds=secondes))

    def test_jeton_valide_rendu_tel_quel(self):
        self.expire_dans(3600)
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.json()['access_token'], JETON_ALICE)
        self.http_post.assert_not_called()

    def test_jeton_expire_renouvele_avant_d_etre_rendu(self):
        self.expire_dans(-10)
        self.simule_jeton({'access_token': 'NOUVEAU-JETON', 'refresh_token': 'NOUVEAU-RENOUV',
                           'expires_in': 3600})
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['access_token'], 'NOUVEAU-JETON')
        (url,), kwargs = self.http_post.call_args
        self.assertEqual(url, 'https://forge.example/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid-forge', 'client_secret': SECRET_SITE,
            'grant_type': 'refresh_token', 'refresh_token': RENOUV_ALICE,
        })
        relu = Connection.objects.get()
        self.assertEqual((relu.access_token, relu.refresh_token), ('NOUVEAU-JETON', 'NOUVEAU-RENOUV'))
        self.assertFalse(relu.is_expired)
        brut = colonnes_brutes('connections')
        self.assertNotIn('NOUVEAU-JETON', brut)
        self.assertNotIn('NOUVEAU-RENOUV', brut)
        # La seconde demande ne retourne pas chez le site.
        self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(self.http_post.call_count, 1)

    def test_marge_de_soixante_secondes(self):
        """Un jeton qui expire pendant le trajet n'est jamais servi."""
        self.expire_dans(30)
        self.simule_jeton({'access_token': 'NOUVEAU-JETON', 'expires_in': 3600})
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.json()['access_token'], 'NOUVEAU-JETON')
        # Renouvellement sans nouveau refresh_token : l'ancien est gardé.
        self.assertEqual(Connection.objects.get().refresh_token, RENOUV_ALICE)

    def test_juste_au_dela_de_la_marge_pas_de_renouvellement(self):
        self.expire_dans(120)
        self.assertEqual(self.get('/api/providers/forge/token/', self.alice).json()['access_token'],
                         JETON_ALICE)
        self.http_post.assert_not_called()

    def test_expire_sans_moyen_de_renouveler(self):
        self.expire_dans(-10, refresh='')
        resp = self.get('/api/providers/forge/token/', self.alice)
        self.assertEqual(resp.status_code, 409)
        self.assertNotIn(JETON_ALICE, resp.content.decode())
        self.assertIn('connect_url', resp.json())
        self.http_post.assert_not_called()
        self.assertFalse(self.get('/api/providers/forge/status/', self.alice).json()['connected'])

    def test_renouvellement_refuse_ou_site_injoignable(self):
        """Le jeton périmé n'est jamais rendu, et rien n'est journalisé comme remis."""
        self.expire_dans(-10)
        cas = {
            'refuse': dict(return_value=reponse(400, {'error': 'invalid_grant'})),
            'erreur_en_200': dict(return_value=reponse(200, {'error': 'invalid_grant'})),
            'injoignable': dict(side_effect=requests.ConnectionError('coupé')),
        }
        for nom, comportement in cas.items():
            with self.subTest(cas=nom):
                self.http_post.reset_mock(return_value=True, side_effect=True)
                self.http_post.configure_mock(**comportement)
                with self.assertLogs('api.views', level='INFO') as journal:
                    resp = self.get('/api/providers/forge/token/', self.alice)
                self.assertEqual(resp.status_code, 409)
                self.assertNotIn(JETON_ALICE, resp.content.decode())
                self.assertEqual([r.levelname for r in journal.records], ['WARNING'])
                self.assertNotIn(RENOUV_ALICE, journal.output[0])
        self.assertEqual(Connection.objects.get().access_token, JETON_ALICE)
