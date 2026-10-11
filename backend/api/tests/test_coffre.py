"""Le coffre : sites OAuth, liste des apps autorisées, chiffrement au repos.

Trois propriétés tenues ici :
  • un `client_secret` déposé ne ressort jamais de l'API, sous aucune forme ;
  • seuls les groupes de `OAUTH_HUB_ADMIN_GROUPS` écrivent ;
  • ce qui est en base est chiffré, et illisible avec une autre clé.
"""
from __future__ import annotations

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured

from api import crypto
from api.models import Connection, Provider, TrustedClient

from .base import (
    CLIENTS_DU_REALM, DEV, HUB, MEMBRE, SECRET_SITE, HubTestCase, colonnes_brutes, make_connection,
    make_provider, token,
)

NOUVEAU_SITE = {
    'slug': 'depot',
    'display_name': 'Dépôt',
    'authorization_url': 'https://depot.example/oauth/authorize',
    'token_url': 'https://depot.example/oauth/token',
    'client_id': 'cid-depot',
    'client_secret': 'secret-depot-abcdef',
    'default_scopes': 'read write',
    'scope_separator': ' ',
}


class SitesTests(HubTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.site = make_provider()
        self.dev = token('dan', DEV)
        self.membre = token('alice', MEMBRE)

    # ── Qui écrit ─────────────────────────────────────────────────────────────
    def test_un_membre_lit_mais_n_ecrit_pas(self):
        self.assertEqual(self.get('/api/providers/', self.membre).status_code, 200)
        self.assertEqual(self.get('/api/providers/forge/', self.membre).status_code, 200)
        essais = [
            ('post', '/api/providers/', NOUVEAU_SITE),
            ('patch', '/api/providers/forge/', {'token_url': 'https://pirate.example/t'}),
            ('put', '/api/providers/forge/', NOUVEAU_SITE),
            ('delete', '/api/providers/forge/', None),
        ]
        for method, path, data in essais:
            with self.subTest(method=method):
                resp = self.call(method, path, self.membre, data)
                self.assertEqual(resp.status_code, 403)
                self.assertIn('développeurs', resp.json()['detail'])
        self.site.refresh_from_db()
        self.assertEqual(self.site.token_url, 'https://forge.example/oauth/token')
        self.assertEqual(Provider.objects.count(), 1)

    def test_le_groupe_d_administration_vient_du_reglage(self):
        with self.settings(OAUTH_HUB_ADMIN_GROUPS='gardiens'):
            refus = self.call('patch', '/api/providers/forge/', self.dev, {'notes': 'x'})
            self.assertEqual(refus.status_code, 403)
        with self.settings(OAUTH_HUB_ADMIN_GROUPS='', KEYCLOAK_REQUIRED_GROUPS='developers'):
            refus = self.call('patch', '/api/providers/forge/', self.dev, {'notes': 'x'})
            self.assertEqual(refus.status_code, 403)

    def test_un_dev_cree_un_site(self):
        resp = self.call('post', '/api/providers/', self.dev, NOUVEAU_SITE)
        self.assertEqual(resp.status_code, 201, resp.data)
        cree = Provider.objects.get(pk='depot')
        self.assertEqual(cree.client_secret, 'secret-depot-abcdef')
        self.assertEqual(cree.updated_by, 'dan@ssolab.local')
        self.assertTrue(resp.json()['has_client_secret'])
        self.assertTrue(resp.json()['is_configured'])

    def test_updated_by_vient_du_jeton_pas_de_la_requete(self):
        self.call('patch', '/api/providers/forge/', self.dev,
                  {'notes': 'x', 'updated_by': 'quelquun@autre.example'})
        self.site.refresh_from_db()
        self.assertEqual(self.site.updated_by, 'dan@ssolab.local')

    # ── Le secret ne ressort jamais ───────────────────────────────────────────
    def test_le_secret_ne_ressort_d_aucune_reponse(self):
        chiffre = self.site.client_secret_encrypted
        reponses = [
            self.get('/api/providers/', self.dev),
            self.get('/api/providers/forge/', self.dev),
            self.get('/api/providers/forge/status/', self.dev),
            self.get('/api/providers/forge/authorize/', self.dev),
            self.call('patch', '/api/providers/forge/', self.dev, {'notes': 'relu'}),
            self.call('put', '/api/providers/forge/', self.dev,
                      {**NOUVEAU_SITE, 'slug': 'forge', 'client_secret': SECRET_SITE}),
            self.call('post', '/api/providers/', self.dev, NOUVEAU_SITE),
            self.call('options', '/api/providers/forge/', self.dev),
        ]
        for resp in reponses:
            with self.subTest(resp=resp.request['PATH_INFO'], method=resp.request['REQUEST_METHOD']):
                self.assertLess(resp.status_code, 300, resp.content)
                corps = resp.content.decode()
                self.assertNotIn(SECRET_SITE, corps)
                self.assertNotIn('secret-depot-abcdef', corps)
                self.assertNotIn(chiffre, corps)
                self.assertNotIn('client_secret_encrypted', corps)
        fiche = self.get('/api/providers/forge/', self.dev).json()
        self.assertNotIn('client_secret', fiche)
        self.assertIs(fiche['has_client_secret'], True)

    def test_secret_vide_ou_absent_conserve_l_ancien(self):
        for data in ({'client_secret': '', 'notes': 'a'}, {'notes': 'b'}):
            with self.subTest(data=data):
                resp = self.call('patch', '/api/providers/forge/', self.dev, data)
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(Provider.objects.get(pk='forge').client_secret, SECRET_SITE)

    def test_secret_saisi_remplace_l_ancien(self):
        self.call('patch', '/api/providers/forge/', self.dev, {'client_secret': 'nouveau-secret'})
        self.assertEqual(Provider.objects.get(pk='forge').client_secret, 'nouveau-secret')

    def test_site_sans_secret_ou_desactive_non_connectable(self):
        make_provider('vide', secret='')
        make_provider('coupe', enabled=False)
        make_provider('sansid', client_id='')
        etats = {s['slug']: s for s in self.get('/api/providers/', self.membre).json()}
        self.assertTrue(etats['forge']['is_configured'])
        for slug in ('vide', 'coupe', 'sansid'):
            with self.subTest(slug=slug):
                self.assertFalse(etats[slug]['is_configured'])
                resp = self.get(f'/api/providers/{slug}/authorize/', self.membre)
                self.assertEqual(resp.status_code, 400)
        self.assertFalse(etats['vide']['has_client_secret'])

    def test_l_uri_de_rappel_est_celle_du_serveur(self):
        attendu = 'https://lab.example/oauth-hub-api/api/callback/forge/'
        self.assertEqual(self.get('/api/providers/', self.membre).json()[0]['callback_uri'], attendu)
        self.assertEqual(self.get('/api/providers/forge/', self.membre).json()['callback_uri'], attendu)

    def test_separateur_de_portees(self):
        """Un espace est rogné par DRF par défaut ; un séparateur vide collerait
        les portées entre elles."""
        for envoye, garde in ((' ', ' '), ('', ' '), (',', ',')):
            with self.subTest(envoye=envoye):
                resp = self.call('patch', '/api/providers/forge/', self.dev,
                                 {'scope_separator': envoye})
                self.assertEqual(resp.status_code, 200, resp.data)
                self.assertEqual(Provider.objects.get(pk='forge').scope_separator, garde)
        self.assertEqual(Provider(default_scopes='a b', scope_separator='').scopes_as_param(), 'a b')
        self.assertEqual(Provider(default_scopes='a b', scope_separator=',').scopes_as_param(), 'a,b')

    def test_supprimer_un_site_supprime_ses_connexions_et_le_trace(self):
        make_connection(self.site, 'alice', 'jeton-alice')
        make_connection(self.site, 'bob', 'jeton-bob')
        with self.assertLogs('api.views', level='WARNING') as journal:
            resp = self.call('delete', '/api/providers/forge/', self.dev)
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(Connection.objects.count(), 0)
        ligne = '\n'.join(journal.output)
        self.assertIn('forge', ligne)
        self.assertIn('dan@ssolab.local', ligne)
        self.assertIn('2 connexion', ligne)

    # ── Défauts corrigés (dérogation de l'architecte à I4) ────────────────────
    def test_le_slug_ne_se_modifie_pas(self):
        """`slug` est la clé primaire : inscriptible, un PATCH qui le change
        insérerait une seconde fiche avec le secret recopié."""
        for method, data in (('patch', {'slug': 'forge2', 'notes': 'n'}),
                             ('put', {**NOUVEAU_SITE, 'slug': 'forge3'})):
            with self.subTest(method=method):
                resp = self.call(method, '/api/providers/forge/', self.dev, data)
                self.assertEqual(resp.status_code, 200, resp.content)
                self.assertEqual(resp.json()['slug'], 'forge')
                self.assertEqual(list(Provider.objects.values_list('slug', flat=True)), ['forge'])
        self.assertEqual(Provider.objects.get().notes, 'n')     # le reste du PATCH s'applique
        # À la création il se choisit toujours, et reste unique.
        self.assertEqual(self.call('post', '/api/providers/', self.dev, NOUVEAU_SITE).status_code, 201)
        self.assertEqual(self.call('post', '/api/providers/', self.dev, NOUVEAU_SITE).status_code, 400)

    def test_une_app_tierce_ne_modifie_pas_un_site(self):
        """Même garde que la liste des apps autorisées (`WritableFromHubOnly`) :
        une app tierce autorisée, avec le jeton d'un dev qui l'utilise, ne
        réécrit pas `token_url` — le prochain échange lui enverrait le
        `client_secret` du lab et le jeton de renouvellement de l'utilisateur.
        La lecture, elle, lui reste ouverte."""
        TrustedClient.objects.create(client_id='app-tierce')
        dev_via_app = token('dan', DEV, azp='app-tierce')
        essais = [
            ('post', '/api/providers/', NOUVEAU_SITE),
            ('patch', '/api/providers/forge/', {'token_url': 'https://pirate.example/oauth/token'}),
            ('put', '/api/providers/forge/', {**NOUVEAU_SITE, 'slug': 'forge'}),
            ('delete', '/api/providers/forge/', None),
        ]
        for method, path, data in essais:
            with self.subTest(method=method):
                resp = self.call(method, path, dev_via_app, data)
                self.assertEqual(resp.status_code, 403)
                self.assertIn("depuis l'interface", resp.json()['detail'])
        self.site.refresh_from_db()
        self.assertEqual(self.site.token_url, 'https://forge.example/oauth/token')
        self.assertEqual(list(Provider.objects.values_list('slug', flat=True)), ['forge'])
        self.assertEqual(self.get('/api/providers/', dev_via_app).status_code, 200)
        self.assertEqual(self.get('/api/providers/forge/', dev_via_app).status_code, 200)


class AppsAutoriseesTests(HubTestCase):

    def setUp(self) -> None:
        super().setUp()
        self.dev = token('dan', DEV)
        self.membre = token('alice', MEMBRE)

    def test_la_liste_commence_par_oauth_hub_verrouillee(self):
        TrustedClient.objects.create(client_id='app-b')
        lignes = self.get('/api/trusted-clients/', self.membre).json()
        self.assertEqual([l['client_id'] for l in lignes], [HUB, 'app-b'])
        self.assertEqual([l['locked'] for l in lignes], [True, False])

    def test_un_membre_n_ecrit_pas(self):
        TrustedClient.objects.create(client_id='app-b')
        essais = [
            ('post', '/api/trusted-clients/', {'client_id': 'complice'}),
            ('patch', '/api/trusted-clients/app-b/', {'enabled': False}),
            ('delete', '/api/trusted-clients/app-b/', None),
        ]
        for method, path, data in essais:
            with self.subTest(method=method):
                self.assertEqual(self.call(method, path, self.membre, data).status_code, 403)
        self.assertEqual(list(TrustedClient.objects.values_list('client_id', 'enabled')),
                         [('app-b', True)])

    def test_un_dev_n_ecrit_pas_au_travers_d_une_app_tierce(self):
        """Une app déjà autorisée, avec le jeton d'un dev qui l'utilise, ne
        s'ajoute pas de complices."""
        TrustedClient.objects.create(client_id='app-b')
        dev_via_app = token('dan', DEV, azp='app-b')
        self.assertEqual(self.get('/api/trusted-clients/', dev_via_app).status_code, 200)
        essais = [
            ('post', '/api/trusted-clients/', {'client_id': 'complice'}),
            ('patch', '/api/trusted-clients/app-b/', {'description': 'x'}),
            ('delete', '/api/trusted-clients/app-b/', None),
        ]
        for method, path, data in essais:
            with self.subTest(method=method):
                resp = self.call(method, path, dev_via_app, data)
                self.assertEqual(resp.status_code, 403)
                self.assertIn("depuis l'interface", resp.json()['detail'])
        self.assertFalse(TrustedClient.objects.filter(pk='complice').exists())

    def test_autoriser_puis_revoquer_de_bout_en_bout(self):
        app = token('alice', MEMBRE, azp='nouvelle-app')
        self.assertRefuse(self.get('/api/me/', app))

        with self.assertLogs('api.views', level='WARNING') as journal:
            resp = self.call('post', '/api/trusted-clients/', self.dev,
                             {'client_id': 'nouvelle-app', 'description': 'essai',
                              'updated_by': 'faux@autre.example'})
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertIn('nouvelle-app', journal.output[0])
        self.assertIn('dan@ssolab.local', journal.output[0])
        self.assertEqual(TrustedClient.objects.get(pk='nouvelle-app').updated_by, 'dan@ssolab.local')
        self.assertEqual(self.get('/api/me/', app).status_code, 200)

        with self.assertLogs('api.views', level='WARNING') as journal:
            self.call('patch', '/api/trusted-clients/nouvelle-app/', self.dev, {'enabled': False})
        self.assertIn('DÉSACTIVÉ', journal.output[0])
        self.assertRefuse(self.get('/api/me/', app))

        with self.assertLogs('api.views', level='WARNING') as journal:
            self.call('patch', '/api/trusted-clients/nouvelle-app/', self.dev, {'enabled': True})
        self.assertIn('RÉACTIVÉ', journal.output[0])
        self.assertEqual(self.get('/api/me/', app).status_code, 200)

        with self.assertLogs('api.views', level='WARNING') as journal:
            resp = self.call('delete', '/api/trusted-clients/nouvelle-app/', self.dev)
        self.assertEqual(resp.status_code, 204)
        self.assertIn('RÉVOQUÉ', journal.output[0])
        self.assertRefuse(self.get('/api/me/', app))

    def test_saisies_refusees(self):
        refusees = [
            *CLIENTS_DU_REALM,                            # clients intégrés du realm
            HUB,                                          # autorisé en dur, pas de ligne
            '*', 'app-*', 'app b', '-app', 'app/b', 'app,b', '',
        ]
        for client_id in refusees:
            with self.subTest(client_id=client_id):
                resp = self.call('post', '/api/trusted-clients/', self.dev, {'client_id': client_id})
                self.assertEqual(resp.status_code, 400, resp.data)
        self.assertEqual(TrustedClient.objects.count(), 0)

    def test_le_client_id_ne_se_modifie_pas(self):
        """Le changer reviendrait à révoquer une app et en autoriser une autre
        sous couvert d'une correction."""
        TrustedClient.objects.create(client_id='app-b')
        resp = self.call('patch', '/api/trusted-clients/app-b/', self.dev,
                         {'client_id': 'admin-cli', 'description': 'x'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(list(TrustedClient.objects.values_list('client_id', flat=True)), ['app-b'])


class ChiffrementTests(HubTestCase):

    def test_aller_retour_et_valeur_vide(self):
        chiffre = crypto.encrypt('jeton-amont')
        self.assertNotIn('jeton-amont', chiffre)
        self.assertEqual(crypto.decrypt(chiffre), 'jeton-amont')
        self.assertNotEqual(chiffre, crypto.encrypt('jeton-amont'))  # aléa par chiffrement
        self.assertEqual(crypto.encrypt(''), '')
        self.assertEqual(crypto.decrypt(''), '')

    def test_rien_en_clair_dans_la_base(self):
        site = make_provider(secret='SECRET-EN-CLAIR-SITE')
        make_connection(site, 'alice', 'JETON-EN-CLAIR-ACCES', 'JETON-EN-CLAIR-RENOUV')
        for table in ('providers', 'connections'):
            brut = colonnes_brutes(table)
            self.assertNotIn('EN-CLAIR', brut, table)
        relu = Connection.objects.get()
        self.assertEqual(relu.access_token, 'JETON-EN-CLAIR-ACCES')
        self.assertEqual(relu.refresh_token, 'JETON-EN-CLAIR-RENOUV')
        self.assertEqual(Provider.objects.get().client_secret, 'SECRET-EN-CLAIR-SITE')

    def test_une_autre_cle_ne_dechiffre_rien(self):
        """Erreur franche et non chaîne vide : rendre '' ferait croire que
        l'utilisateur n'a jamais relié le site."""
        chiffre = crypto.encrypt('jeton-amont')
        crypto._fernet = None
        with self.settings(OAUTH_HUB_ENCRYPTION_KEY=Fernet.generate_key().decode()):
            with self.assertRaises(ValueError):
                crypto.decrypt(chiffre)
        with self.assertRaises(ValueError):
            crypto.decrypt('pas-un-jeton-fernet')

    def test_cle_absente_ou_invalide(self):
        for cle in ('', '   ', 'trop-courte'):
            crypto._fernet = None
            with self.subTest(cle=cle), self.settings(OAUTH_HUB_ENCRYPTION_KEY=cle):
                with self.assertRaises(ImproperlyConfigured):
                    crypto.encrypt('x')
        crypto._fernet = None
