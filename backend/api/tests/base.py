"""Socle commun des tests d'oauth-hub.

Ce qui est RÉEL : la classe d'authentification (signature RS256, expiration,
`azp`, groupes, email), les permissions, les vues, les sérialiseurs, le
chiffrement Fernet, la base PostgreSQL.

Ce qui est SIMULÉ, et seulement cela :
  • le téléchargement du JWKS de Keycloak (remplacé par une clé RSA locale) ;
  • les appels HTTP au fournisseur externe (`requests.post` / `requests.get`
    d'`api.oauth`). Par défaut ils lèvent : un test qui partirait sur le réseau
    sans l'avoir prévu échoue bruyamment au lieu d'attendre.
"""
from __future__ import annotations

import json
import time
from unittest import mock

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import connection as db
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from api import crypto
from api.authentication import KeycloakJWTAuthentication
from api.models import Connection, Provider, TrustedClient

HUB = 'oauth-hub'
LAB = 'lab.example'
BACKEND_URL = f'https://{LAB}/oauth-hub-api'
FRONTEND_URL = f'https://{LAB}/oauth-hub'
ISSUER = f'https://{LAB}/auth/realms/ssolab'

# Clients intégrés d'un realm Keycloak. Écrits ICI, et non lus dans
# `TrustedClient.RESERVED_CLIENT_IDS` : un test qui tirerait sa liste de la
# constante qu'il vérifie passerait encore si on la vidait.
CLIENTS_DU_REALM = ['account', 'account-console', 'admin-cli', 'broker',
                    'realm-management', 'security-admin-console']

DEV = ['developers']
MEMBRE = ['famille']

_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
AUTRE_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _LocalJwks:
    """Remplace le TÉLÉCHARGEMENT du JWKS ; la vérification reste réelle."""

    class _Key:
        key = _RSA.public_key()

    def get_signing_key_from_jwt(self, token):
        return self._Key()


_ABSENT = object()


def token(uid: str = 'alice', groups=MEMBRE, azp=HUB, *, email=_ABSENT,
          exp_in: int = 300, key=_RSA, algorithm: str = 'RS256') -> str:
    """Un jeton tel que Keycloak l'émettrait, signé par la clé locale."""
    claims = {
        'preferred_username': uid,
        'exp': int(time.time()) + exp_in,
        'iat': int(time.time()) - 5,
    }
    if groups is not None:
        claims['groups'] = groups
    if azp is not None:
        claims['azp'] = azp
    if email is _ABSENT:
        email = f'{uid}@ssolab.local'
    if email is not None:
        claims['email'] = email
    return jwt.encode(claims, key, algorithm=algorithm)


def reponse(status: int = 200, payload=None, text: str = ''):
    """Une réponse `requests` simulée. `payload=None` ⇒ corps non JSON."""
    import requests

    r = mock.Mock()
    r.status_code = status
    r.text = text
    if payload is None:
        r.json.side_effect = ValueError('pas du JSON')
    else:
        r.json.return_value = payload
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f'HTTP {status}')
    return r


SECRET_SITE = 'secret-du-site-forge-0123456789'


def make_provider(slug: str = 'forge', secret: str = SECRET_SITE, **extra) -> Provider:
    fields = dict(
        slug=slug,
        display_name=slug.capitalize(),
        authorization_url=f'https://{slug}.example/oauth/authorize',
        token_url=f'https://{slug}.example/oauth/token',
        client_id=f'cid-{slug}',
        default_scopes='read:user repo',
    )
    fields.update(extra)
    provider = Provider(**fields)
    provider.client_secret = secret
    provider.save()
    return provider


def make_connection(provider: Provider, uid: str, access: str, refresh: str = '',
                    **extra) -> Connection:
    connection = Connection(provider=provider, user_email=f'{uid}@ssolab.local', **extra)
    connection.access_token = access
    connection.refresh_token = refresh
    connection.save()
    return connection


def colonnes_brutes(table: str) -> str:
    """Le contenu de la table tel qu'un dump SQL le montrerait."""
    with db.cursor() as cursor:
        cursor.execute(f'SELECT * FROM {table}')
        return json.dumps(cursor.fetchall(), default=str)


@override_settings(
    KEYCLOAK_CLIENT_ID=HUB,
    KEYCLOAK_REQUIRED_GROUPS='developers,famille,amis',
    KEYCLOAK_ISSUER_URI=ISSUER,
    OAUTH_HUB_ADMIN_GROUPS='developers',
    OAUTH_HUB_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    OAUTH_HUB_BACKEND_PUBLIC_URL=BACKEND_URL,
    OAUTH_HUB_FRONTEND_PUBLIC_URL=FRONTEND_URL,
    OAUTH_HUB_ALLOWED_RETURN_HOSTS=LAB,
)
class HubTestCase(TestCase):

    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(
            KeycloakJWTAuthentication, '_get_jwks_client',
            classmethod(lambda cls: _LocalJwks()),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # La clé Fernet est mémorisée par processus : repartir de celle du test.
        fernet = mock.patch.object(crypto, '_fernet', None)
        fernet.start()
        self.addCleanup(fernet.stop)

        # Réseau fermé par défaut.
        non_simule = AssertionError('appel réseau non simulé vers le fournisseur')
        self.http_post = self._patch('api.oauth.requests.post', side_effect=non_simule)
        self.http_get = self._patch('api.oauth.requests.get', side_effect=non_simule)

        # Les migrations 0002 et 0003 sèment des sites et, depuis le `.env`, des
        # clients autorisés : les tests partent d'une table connue.
        TrustedClient.objects.all().delete()
        Provider.objects.all().delete()

    def _patch(self, target: str, **kwargs):
        patcher = mock.patch(target, **kwargs)
        started = patcher.start()
        self.addCleanup(patcher.stop)
        return started

    # ── Appels ────────────────────────────────────────────────────────────────
    def call(self, method: str, path: str, tok: str | None = None, data=None, **extra):
        client = APIClient()
        if tok is not None:
            extra['HTTP_AUTHORIZATION'] = f'Bearer {tok}'
        if method == 'get':
            return client.get(path, data or {}, **extra)
        return getattr(client, method)(path, data or {}, format='json', **extra)

    def get(self, path: str, tok: str | None = None, data=None):
        return self.call('get', path, tok, data)

    def simule_jeton(self, payload: dict, status: int = 200) -> None:
        """Le fournisseur répond `payload` à l'échange ou au renouvellement."""
        self.http_post.side_effect = None
        self.http_post.return_value = reponse(status, payload)

    def assertRefuse(self, resp, fragment: str | None = None) -> None:
        self.assertIn(resp.status_code, (401, 403), getattr(resp, 'data', resp))
        if fragment is not None:
            self.assertIn(fragment, str(resp.json().get('detail', '')))
