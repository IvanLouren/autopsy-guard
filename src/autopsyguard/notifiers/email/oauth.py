"""OAuth2 helpers for SMTP XOAUTH2 authentication (Google / Microsoft)."""

from __future__ import annotations

import base64
import json
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any


class SMTPOAuthError(RuntimeError):
    """Raised when OAuth token exchange/refresh fails."""


@dataclass(frozen=True)
class OAuthProviderSpec:
    provider: str
    authorize_url: str
    token_url: str
    scope: str


def get_provider_spec(provider: str, tenant: str = "common") -> OAuthProviderSpec:
    p = (provider or "").strip().lower()
    if p == "google":
        return OAuthProviderSpec(
            provider="google",
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            scope="https://mail.google.com/",
        )
    if p == "microsoft":
        issuer = (tenant or "common").strip()
        base = f"https://login.microsoftonline.com/{issuer}/oauth2/v2.0"
        return OAuthProviderSpec(
            provider="microsoft",
            authorize_url=f"{base}/authorize",
            token_url=f"{base}/token",
            scope="offline_access https://outlook.office.com/SMTP.Send",
        )
    raise SMTPOAuthError(f"Unsupported OAuth provider: {provider!r}")


def make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge)."""
    verifier = secrets.token_urlsafe(64).rstrip("=")
    challenge = base64.urlsafe_b64encode(sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return verifier, challenge


def build_authorization_url(
    *,
    provider: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    login_hint: str,
    tenant: str = "common",
) -> str:
    spec = get_provider_spec(provider, tenant=tenant)
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": spec.scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if login_hint:
        params["login_hint"] = login_hint
    if spec.provider == "google":
        params["access_type"] = "offline"
        params["prompt"] = "consent"
    else:
        params["response_mode"] = "query"
        params["prompt"] = "select_account"
    return f"{spec.authorize_url}?{urllib.parse.urlencode(params)}"


def exchange_authorization_code(
    *,
    provider: str,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    client_secret: str = "",
    tenant: str = "common",
    timeout: float = 30.0,
) -> dict[str, Any]:
    spec = get_provider_spec(provider, tenant=tenant)
    body = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if client_secret:
        body["client_secret"] = client_secret
    return _oauth_post_json(spec.token_url, body, timeout=timeout)


def refresh_access_token(
    *,
    provider: str,
    refresh_token: str,
    client_id: str,
    client_secret: str = "",
    tenant: str = "common",
    timeout: float = 30.0,
) -> dict[str, Any]:
    spec = get_provider_spec(provider, tenant=tenant)
    body = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if client_secret:
        body["client_secret"] = client_secret
    return _oauth_post_json(spec.token_url, body, timeout=timeout)


def load_token_file(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SMTPOAuthError(f"Could not read OAuth token file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SMTPOAuthError(f"Invalid OAuth token JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise SMTPOAuthError(f"OAuth token file must be a JSON object: {path}")
    return raw


def save_token_file(path: Path, token_data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(token_data, indent=2, ensure_ascii=False), encoding="utf-8")


def xoauth2_initial_response(user: str, access_token: str) -> str:
    payload = f"user={user}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def token_is_fresh(token_data: dict[str, Any], min_valid_seconds: int = 60) -> bool:
    expires_at = float(token_data.get("expires_at") or 0.0)
    return expires_at > (time.time() + min_valid_seconds)


def _oauth_post_json(url: str, body: dict[str, str], *, timeout: float) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(body).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SMTPOAuthError(f"OAuth token request failed: {exc}") from exc
    if not isinstance(data, dict) or "access_token" not in data:
        raise SMTPOAuthError(f"OAuth token response missing access_token: {data!r}")
    return data
