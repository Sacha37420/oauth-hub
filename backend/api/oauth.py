"""Client OAuth2 générique — la seule partie qui parle aux sites externes.

Aucune connaissance d'un site particulier ici : tout ce qui change d'un
fournisseur à l'autre (URLs, séparateur de portées, PKCE) vient du Provider en
base. C'est ce qui permet d'ajouter GitLab ou Google par un formulaire au lieu
d'un déploiement.

Les écarts au standard qu'on absorbe quand même, parce qu'ils sont universels
en pratique :
  • `Accept: application/json` — sans lui, GitHub répond en form-urlencoded.
  • une erreur peut arriver en **HTTP 200** avec un champ `error` dans le corps
    (GitHub le fait) ; le code de statut seul ne suffit donc jamais à conclure.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlencode

import requests
from django.utils import timezone

from .models import Provider

# Un site injoignable ou lent ne doit pas immobiliser un worker Django.
HTTP_TIMEOUT = 15


class OAuthError(Exception):
    """Échec côté site externe (refus, code périmé, identifiants faux…)."""


@dataclass
class TokenResponse:
    access_token: str
    token_type: str = 'bearer'
    scope: str = ''
    refresh_token: str = ''
    expires_at: object | None = None


# ── Aléa du flux ──────────────────────────────────────────────────────────────

def new_state() -> str:
    """`state` anti-CSRF, aussi utilisé comme clé primaire de PendingAuthorization."""
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(64)[:128]


def code_challenge_for(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


# ── Aller : construction de l'URL d'autorisation ──────────────────────────────

def build_authorization_url(
    provider: Provider,
    *,
    state: str,
    redirect_uri: str,
    scopes: str = '',
    code_verifier: str = '',
) -> str:
    params = {
        'client_id': provider.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'state': state,
    }
    scope_param = provider.scopes_as_param(scopes)
    if scope_param:
        params['scope'] = scope_param
    if provider.use_pkce and code_verifier:
        params['code_challenge'] = code_challenge_for(code_verifier)
        params['code_challenge_method'] = 'S256'
    separator = '&' if '?' in provider.authorization_url else '?'
    return f'{provider.authorization_url}{separator}{urlencode(params)}'


# ── Retour : échange du code contre un jeton ──────────────────────────────────

def _parse_token_payload(payload: dict) -> TokenResponse:
    if payload.get('error'):
        raise OAuthError(
            payload.get('error_description') or payload['error']
        )
    access_token = payload.get('access_token')
    if not access_token:
        raise OAuthError(
            "Réponse du site sans champ 'access_token' — identifiants ou URL "
            "de jeton probablement erronés."
        )

    expires_at = None
    expires_in = payload.get('expires_in')
    if expires_in:
        try:
            expires_at = timezone.now() + timedelta(seconds=int(expires_in))
        except (TypeError, ValueError):
            # Un site qui renvoie un `expires_in` non numérique est hors norme ;
            # on préfère traiter le jeton comme non-expirant plutôt que de faire
            # échouer une connexion par ailleurs valide.
            expires_at = None

    return TokenResponse(
        access_token=access_token,
        token_type=payload.get('token_type') or 'bearer',
        scope=payload.get('scope') or '',
        refresh_token=payload.get('refresh_token') or '',
        expires_at=expires_at,
    )


def _post_token(provider: Provider, data: dict) -> TokenResponse:
    try:
        response = requests.post(
            provider.token_url,
            data=data,
            headers={'Accept': 'application/json'},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OAuthError(f'Site injoignable : {exc}') from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise OAuthError(
            f'Réponse illisible du site (HTTP {response.status_code}) : '
            f'{response.text[:200]}'
        ) from exc

    if response.status_code >= 400:
        raise OAuthError(
            payload.get('error_description')
            or payload.get('error')
            or f'HTTP {response.status_code}'
        )
    return _parse_token_payload(payload)


def exchange_code(
    provider: Provider,
    *,
    code: str,
    redirect_uri: str,
    code_verifier: str = '',
) -> TokenResponse:
    data = {
        'client_id': provider.client_id,
        'client_secret': provider.client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        # Rejouée à l'identique : la plupart des sites la revérifient et
        # refusent l'échange si elle diffère d'un caractère.
        'redirect_uri': redirect_uri,
    }
    if provider.use_pkce and code_verifier:
        data['code_verifier'] = code_verifier
    return _post_token(provider, data)


def refresh_access_token(provider: Provider, *, refresh_token: str) -> TokenResponse:
    return _post_token(provider, {
        'client_id': provider.client_id,
        'client_secret': provider.client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    })


# ── Confort : quel compte a été relié ─────────────────────────────────────────

def fetch_account_label(provider: Provider, access_token: str) -> str:
    """Récupère un libellé lisible du compte relié. Best-effort par nature.

    Purement cosmétique : un échec ne doit jamais faire rater une connexion par
    ailleurs réussie, sinon on perdrait un jeton valide pour un défaut
    d'affichage.
    """
    if not provider.account_url:
        return ''
    try:
        response = requests.get(
            provider.account_url,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            },
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return ''
    value = payload.get(provider.account_label_field or 'login')
    return str(value) if value else ''
