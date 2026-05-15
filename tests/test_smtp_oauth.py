from __future__ import annotations

import base64
import time
import urllib.parse

from autopsyguard.notifiers.email.oauth import (
    build_authorization_url,
    token_is_fresh,
    xoauth2_initial_response,
)


def test_xoauth2_initial_response_format() -> None:
    encoded = xoauth2_initial_response("user@example.com", "token-abc")
    raw = base64.b64decode(encoded).decode("utf-8")
    assert raw == "user=user@example.com\x01auth=Bearer token-abc\x01\x01"


def test_token_is_fresh() -> None:
    now = time.time()
    assert token_is_fresh({"expires_at": now + 3600}) is True
    assert token_is_fresh({"expires_at": now - 1}) is False


def test_build_authorization_url_google() -> None:
    url = build_authorization_url(
        provider="google",
        client_id="cid",
        redirect_uri="http://127.0.0.1:8765/callback",
        code_challenge="abc",
        state="st",
        login_hint="user@example.com",
    )
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    assert parsed.netloc == "accounts.google.com"
    assert q["client_id"] == ["cid"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["access_type"] == ["offline"]
    assert q["scope"] == ["https://mail.google.com/"]
