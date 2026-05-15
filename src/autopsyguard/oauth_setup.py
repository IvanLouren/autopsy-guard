"""Interactive OAuth setup for SMTP (Google / Microsoft)."""

from __future__ import annotations

import argparse
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from autopsyguard.notifiers.email.oauth import (
    SMTPOAuthError,
    build_authorization_url,
    exchange_authorization_code,
    make_pkce_pair,
    save_token_file,
)


@dataclass
class OAuthCallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    result: OAuthCallbackResult = OAuthCallbackResult()
    done_event: threading.Event = threading.Event()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        _CallbackHandler.result.code = _first(params.get("code"))
        _CallbackHandler.result.state = _first(params.get("state"))
        _CallbackHandler.result.error = _first(params.get("error"))

        if _CallbackHandler.result.error:
            body = (
                "<html><body><h2>AutopsyGuard OAuth failed</h2>"
                f"<p>Error: {_CallbackHandler.result.error}</p></body></html>"
            ).encode("utf-8")
            self.send_response(400)
        else:
            body = (
                "<html><body><h2>AutopsyGuard OAuth complete</h2>"
                "<p>You can now close this tab and return to the terminal.</p></body></html>"
            ).encode("utf-8")
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        _CallbackHandler.done_event.set()

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Silence HTTP server request logs for cleaner CLI output.
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="autopsyguard-oauth",
        description="Run browser-based OAuth login and save refresh token for SMTP.",
    )
    parser.add_argument("--provider", required=True, choices=("google",))
    parser.add_argument("--email", required=True, help="Email/account used for SMTP auth")
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", default="")
    parser.add_argument("--port", type=int, default=8765, help="Local callback port (default: 8765)")
    parser.add_argument("--token-file", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=180, help="OAuth callback timeout in seconds")
    parser.add_argument("--no-open-browser", action="store_true", help="Do not auto-open browser")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token_file = args.token_file or _default_token_file(args.provider, args.email)
    redirect_uri = f"http://127.0.0.1:{args.port}/callback"

    try:
        _ensure_port_free(args.port)
    except OSError as exc:
        print(f"Port {args.port} is not available: {exc}")
        return 1

    code_verifier, code_challenge = make_pkce_pair()
    state = secrets.token_urlsafe(24)
    auth_url = build_authorization_url(
        provider=args.provider,
        client_id=args.client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        state=state,
        login_hint=args.email,
    )

    server = HTTPServer(("127.0.0.1", args.port), _CallbackHandler)
    _CallbackHandler.result = OAuthCallbackResult()
    _CallbackHandler.done_event = threading.Event()

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("OAuth callback server listening on", redirect_uri)
    print("Open this URL in your browser and complete login:")
    print(auth_url)

    if not args.no_open_browser:
        try:
            webbrowser.open(auth_url, new=2)
        except Exception:
            pass

    ok = _CallbackHandler.done_event.wait(timeout=max(30, args.timeout))
    server.shutdown()
    server.server_close()

    if not ok:
        print("Timed out waiting for OAuth callback.")
        return 1

    result = _CallbackHandler.result
    if result.error:
        print(f"OAuth error: {result.error}")
        return 1
    if result.state != state:
        print("OAuth state mismatch. Aborting for safety.")
        return 1
    if not result.code:
        print("OAuth did not return an authorization code.")
        return 1

    try:
        token = exchange_authorization_code(
            provider=args.provider,
            code=result.code,
            client_id=args.client_id,
            client_secret=args.client_secret,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            timeout=30.0,
        )
    except SMTPOAuthError as exc:
        print(f"Token exchange failed: {exc}")
        return 1

    now = time.time()
    refresh_token = str(token.get("refresh_token", "")).strip()
    if not refresh_token:
        print("Provider did not return refresh_token. Re-run with a fresh consent flow.")
        return 1

    token_data = {
        "provider": args.provider,
        "email": args.email,
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant": args.tenant,
        "access_token": token["access_token"],
        "refresh_token": refresh_token,
        "token_type": token.get("token_type", "Bearer"),
        "scope": token.get("scope", ""),
        "expires_at": now + max(int(token.get("expires_in", 3600)), 60),
        "updated_at": now,
    }

    save_token_file(token_file, token_data)
    print(f"OAuth token saved to: {token_file}")
    print("Configure AutopsyGuard with smtp_auth_mode: oauth and smtp_oauth_token_file pointing to this file.")
    return 0


def _default_token_file(provider: str, email: str) -> Path:
    safe = email.lower().replace("@", "_at_").replace("/", "_")
    return Path(".autopsyguard") / "oauth" / f"{provider}_{safe}.json"


def _first(values: list[str] | None) -> str | None:
    if not values:
        return None
    return values[0]


def _ensure_port_free(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", port))


if __name__ == "__main__":
    sys.exit(main())
