"""Serrure de l'API (Verrou 2) — vrais jetons signés, classe d'authentification réelle.

Pour oauth-hub le contrôle `azp` n'est pas une égalité : c'est la liste blanche
en base, `TrustedClient.is_trusted`, et ses trois invariants.
"""
from __future__ import annotations

import jwt
from rest_framework.permissions import AllowAny

from api import urls as api_urls
from api.models import TrustedClient
from api.views import CallbackView

from .base import (
    AUTRE_RSA, CLIENTS_DU_REALM, DEV, HUB, MEMBRE, HubTestCase, make_provider, token,
)

CHEMINS_AUTHENTIFIES = [
    ('get', '/api/me/'),
    ('get', '/api/providers/'),
    ('post', '/api/providers/'),
    ('get', '/api/providers/forge/'),
    ('patch', '/api/providers/forge/'),
    ('delete', '/api/providers/forge/'),
    ('get', '/api/providers/forge/authorize/'),
    ('get', '/api/providers/forge/token/'),
    ('get', '/api/providers/forge/status/'),
    ('get', '/api/connections/'),
    ('delete', '/api/connections/forge/'),
    ('get', '/api/trusted-clients/'),
    ('post', '/api/trusted-clients/'),
    ('delete', '/api/trusted-clients/une-app/'),
]


class PorteTests(HubTestCase):

    def setUp(self) -> None:
        super().setUp()
        make_provider()

    def test_sans_jeton_tout_est_refuse(self):
        for method, path in CHEMINS_AUTHENTIFIES:
            with self.subTest(method=method, path=path):
                self.assertRefuse(self.call(method, path))

    def test_le_callback_est_le_seul_endpoint_anonyme(self):
        """Inventaire tiré d'api/urls.py : toute vue ajoutée sans authentification
        ou en AllowAny fait rougir ce test."""
        ouvertes = set()
        for pattern in api_urls.urlpatterns:
            cls = getattr(pattern.callback, 'cls', None) or pattern.callback.view_class
            if AllowAny in cls.permission_classes or list(cls.authentication_classes) == []:
                ouvertes.add(cls)
        self.assertEqual(ouvertes, {CallbackView})

    def test_un_membre_du_lab_entre(self):
        resp = self.get('/api/me/', token('alice', MEMBRE))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {
            'email': 'alice@ssolab.local', 'username': 'alice', 'groups': MEMBRE,
            'is_vault_admin': False, 'client_id': HUB,
        })

    def test_un_dev_est_administrateur_du_coffre(self):
        self.assertTrue(self.get('/api/me/', token('dan', DEV)).json()['is_vault_admin'])

    # ── azp ───────────────────────────────────────────────────────────────────
    def test_admin_cli_est_refuse(self):
        """Le contournement contre lequel le contrôle existe : password grant
        sur le client public `admin-cli`, compte par ailleurs légitime."""
        resp = self.get('/api/me/', token('dan', DEV, azp='admin-cli'))
        self.assertRefuse(resp, "client non autorisé : 'admin-cli'")

    def test_azp_inconnu_ou_absent_est_refuse(self):
        for azp in ('storage', 'oauth-hub-admin', 'OAUTH-HUB', 'oauth-hub ', None):
            with self.subTest(azp=azp):
                self.assertRefuse(self.get('/api/me/', token('dan', DEV, azp=azp)),
                                  'client non autorisé')

    def test_le_client_d_oauth_hub_passe_table_vide(self):
        self.assertEqual(TrustedClient.objects.count(), 0)
        self.assertEqual(self.get('/api/me/', token('alice')).status_code, 200)

    def test_une_app_autorisee_en_base_passe(self):
        TrustedClient.objects.create(client_id='storage-analysis')
        resp = self.get('/api/me/', token('alice', azp='storage-analysis'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['client_id'], 'storage-analysis')

    def test_une_fiche_suspendue_ne_passe_pas(self):
        TrustedClient.objects.create(client_id='storage-analysis', enabled=False)
        self.assertRefuse(self.get('/api/me/', token('alice', azp='storage-analysis')),
                          'client non autorisé')

    def test_revocation_effective_a_la_requete_suivante(self):
        """Invariant 3 — aucun cache : le MÊME jeton, encore valide, est refusé
        dès la requête qui suit la suspension, puis la suppression."""
        fiche = TrustedClient.objects.create(client_id='storage-analysis')
        tok = token('alice', azp='storage-analysis')
        self.assertEqual(self.get('/api/me/', tok).status_code, 200)

        TrustedClient.objects.filter(pk=fiche.pk).update(enabled=False)
        self.assertRefuse(self.get('/api/me/', tok), 'client non autorisé')

        TrustedClient.objects.filter(pk=fiche.pk).update(enabled=True)
        self.assertEqual(self.get('/api/me/', tok).status_code, 200)

        fiche.delete()
        self.assertRefuse(self.get('/api/me/', tok), 'client non autorisé')

    def test_clients_integres_refuses_meme_avec_une_ligne_en_base(self):
        """Invariant 2 — une ligne insérée hors de l'API reste inerte."""
        for client_id in CLIENTS_DU_REALM:
            TrustedClient.objects.create(client_id=client_id, enabled=True)
        for client_id in CLIENTS_DU_REALM:
            with self.subTest(azp=client_id):
                self.assertRefuse(self.get('/api/me/', token('dan', DEV, azp=client_id)),
                                  'client non autorisé')

    # ── groupes, email ────────────────────────────────────────────────────────
    def test_sans_groupe_du_lab_refuse(self):
        for groups in ([], None, ['inconnu'], ['Developers']):
            with self.subTest(groups=groups):
                self.assertRefuse(self.get('/api/me/', token('lea', groups)),
                                  'au moins un groupe')

    def test_liste_de_groupes_vide_ferme_l_app(self):
        """Échec fermé : `KEYCLOAK_REQUIRED_GROUPS` vide ne veut pas dire
        « tout le realm », contrairement au gabarit."""
        for valeur in ('', ' , '):
            with self.subTest(valeur=valeur), self.settings(KEYCLOAK_REQUIRED_GROUPS=valeur):
                self.assertRefuse(self.get('/api/me/', token('dan', DEV)),
                                  'KEYCLOAK_REQUIRED_GROUPS est vide')

    def test_sans_email_refuse(self):
        for email in (None, ''):
            with self.subTest(email=email):
                self.assertRefuse(self.get('/api/me/', token('alice', email=email)),
                                  "claim 'email'")

    # ── signature, expiration, transport ──────────────────────────────────────
    def test_jeton_expire_refuse(self):
        self.assertRefuse(self.get('/api/me/', token('alice', exp_in=-30)), 'Token invalide')

    def test_signature_d_une_autre_cle_refusee(self):
        self.assertRefuse(self.get('/api/me/', token('dan', DEV, key=AUTRE_RSA)),
                          'Token invalide')

    def test_algorithmes_autres_que_rs256_refuses(self):
        sans_signature = token('dan', DEV, key=None, algorithm='none')
        hmac = token('dan', DEV, key='secret-devinable-de-trente-deux-octets!', algorithm='HS256')
        for nom, tok in (('none', sans_signature), ('HS256', hmac)):
            with self.subTest(alg=nom):
                self.assertEqual(jwt.get_unverified_header(tok)['alg'], nom)
                self.assertRefuse(self.get('/api/me/', tok), 'Token invalide')

    def test_jeton_altere_refuse(self):
        entete, corps, signature = token('alice', MEMBRE).split('.')
        _, corps_dev, _ = token('alice', DEV).split('.')
        self.assertRefuse(self.get('/api/me/', f'{entete}.{corps_dev}.{signature}'),
                          'Token invalide')

    def test_pas_de_jeton_dans_l_url(self):
        """Contrairement à `storage`, aucun repli sur `?token=`."""
        tok = token('alice')
        self.assertRefuse(self.get('/api/me/', None, {'token': tok}))
        self.assertRefuse(self.get('/api/me/', None, {'access_token': tok}))


class IsTrustedTests(HubTestCase):
    """`TrustedClient.is_trusted`, seule autorité — testée sans passer par HTTP."""

    def test_table_de_verite(self):
        TrustedClient.objects.create(client_id='app-ok')
        TrustedClient.objects.create(client_id='app-suspendue', enabled=False)
        TrustedClient.objects.create(client_id='admin-cli')
        attendu = {
            HUB: True, 'app-ok': True,
            'app-suspendue': False, 'admin-cli': False, 'inconnue': False,
            'APP-OK': False, 'app-ok ': False, 'app': False, '': False, None: False,
        }
        for azp, verdict in attendu.items():
            with self.subTest(azp=azp):
                self.assertIs(TrustedClient.is_trusted(azp), verdict)

    def test_invariant_1_une_ligne_ne_peut_pas_verrouiller_l_interface(self):
        TrustedClient.objects.create(client_id=HUB, enabled=False)
        self.assertTrue(TrustedClient.is_trusted(HUB))

    def test_invariant_1_suit_le_client_configure(self):
        with self.settings(KEYCLOAK_CLIENT_ID='autre-hub'):
            self.assertTrue(TrustedClient.is_trusted('autre-hub'))
            self.assertFalse(TrustedClient.is_trusted(HUB))

    def test_invariant_2_la_liste_reservee_contient_les_clients_du_realm(self):
        self.assertLessEqual(set(CLIENTS_DU_REALM), set(TrustedClient.RESERVED_CLIENT_IDS))

    def test_invariant_3_la_base_est_lue_a_chaque_appel(self):
        TrustedClient.objects.create(client_id='app-ok')
        for _ in range(3):
            with self.assertNumQueries(1):
                self.assertTrue(TrustedClient.is_trusted('app-ok'))
        with self.assertNumQueries(1):
            self.assertFalse(TrustedClient.is_trusted('inconnue'))
        # Le socle en dur et la liste réservée répondent sans lire la base.
        with self.assertNumQueries(0):
            TrustedClient.is_trusted(HUB)
            TrustedClient.is_trusted('admin-cli')
