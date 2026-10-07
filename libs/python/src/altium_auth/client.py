"""AltiumAuthClient — the public, synchronous API surface."""

from __future__ import annotations

import json
import logging
import time
import uuid
import webbrowser
from base64 import b64encode
from urllib.parse import quote, urlencode, urlparse

from . import _http
from .config import AltiumAuthConfig
from .errors import (
    ActionWaitError,
    ConfigurationError,
    OAuthError,
    StateMismatchError,
    TlsError,
    TransportError,
    _truncate,
)
from .models import AuthorizationRequest, TokenSet, WorkspaceSelection
from .pkce import code_challenge, generate_code_verifier

logger = logging.getLogger("altium_auth")

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_JSON_HEADERS = {"Content-Type": "application/json"}
_MAX_RECONNECTS = 10_000
_DEFAULT_TIMEOUT = 30.0
_SIGN_IN_TIMEOUT = 180.0


def _validate_config(config: AltiumAuthConfig) -> None:
    for name, value in (("client_id", config.client_id), ("scopes", config.scopes)):
        if not value or not value.strip():
            raise ConfigurationError(f"AltiumAuthConfig.{name} is required and must be non-empty.")
    e = config.endpoints
    for name, value in (
        ("authorize_endpoint", e.authorize_endpoint),
        ("token_endpoint", e.token_endpoint),
        ("action_wait_endpoint", e.action_wait_endpoint),
        ("redirect_uri", e.redirect_uri),
    ):
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise ConfigurationError(f'AltiumEndpoints.{name} is not a valid URL: "{value}"')


class AltiumAuthClient:
    """Altium 365 OAuth2/OIDC client (PKCE + ActionWait). Returns tokens; storage is yours."""

    def __init__(self, config: AltiumAuthConfig) -> None:
        _validate_config(config)
        self._config = config
        self._endpoints = config.endpoints

    def create_authorization_url(
        self,
        *,
        redirect_uri: str | None = None,
        state: str | None = None,
        code_verifier: str | None = None,
        scopes: str | None = None,
        select_workspace: WorkspaceSelection = WorkspaceSelection.NONE,
    ) -> AuthorizationRequest:
        """Build a PKCE authorization URL for the redirect-based flow. No network I/O."""
        verifier = code_verifier or generate_code_verifier()
        chosen_state = state or str(uuid.uuid4())
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri or self._endpoints.redirect_uri,
            "scope": scopes or self._config.scopes,
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
            "state": chosen_state,
        }
        if select_workspace in (WorkspaceSelection.STRICT, WorkspaceSelection.OPTIONAL):
            params["selectWorkspace"] = select_workspace.value
        url = f"{self._endpoints.authorize_endpoint}?{urlencode(params)}"
        return AuthorizationRequest(url=url, state=chosen_state, code_verifier=verifier)

    def exchange_code(
        self,
        code: str,
        *,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> TokenSet:
        """Exchange an authorization code for tokens (authorization_code grant)."""
        if not code:
            raise ConfigurationError(
                "code is required — pass the authorization code from the redirect callback."
            )
        body: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self._endpoints.redirect_uri,
        }
        if code_verifier:
            body["code_verifier"] = code_verifier
        return self._token_request(body, timeout)

    def sign_into_workspace(
        self,
        base_access_token: str,
        workspace_auth_id: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> TokenSet:
        """Exchange a global access token for a workspace-scoped token (RFC 8693)."""
        if not base_access_token:
            raise ConfigurationError(
                "base_access_token is required — pass the access_token from a prior sign-in."
            )
        body: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": base_access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": f"a365:workspace:{workspace_auth_id} {self._config.scopes}".strip(),
        }
        return self._token_request(body, timeout)

    def refresh_token(self, refresh_token: str, *, timeout: float = _DEFAULT_TIMEOUT) -> TokenSet:
        """Exchange a refresh token for a fresh TokenSet (no scope is resent)."""
        if not refresh_token:
            raise ConfigurationError(
                "refresh_token is required — pass the refresh_token from a prior TokenSet."
            )
        return self._token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}, timeout
        )

    def revoke_refresh_token(
        self, refresh_token: str, *, timeout: float = _DEFAULT_TIMEOUT
    ) -> None:
        """Revoke a refresh token (RFC 7009). Idempotent: 200 for known/unknown tokens."""
        if not refresh_token:
            raise ConfigurationError(
                "refresh_token is required — pass the refresh_token to revoke."
            )
        endpoint = self._endpoints.token_endpoint.replace("/connect/token", "/connect/revocation")
        body: dict[str, str] = {"token": refresh_token, "token_type_hint": "refresh_token"}
        headers = dict(_FORM_HEADERS)
        self._apply_client_auth(body, headers)
        resp = _http.request(
            "POST", endpoint, headers=headers, data=urlencode(body).encode(), timeout=timeout
        )
        if not 200 <= resp.status < 300:
            raise OAuthError(
                f"Revocation endpoint {resp.status}: {_truncate(resp.text)}", status=resp.status
            )

    @staticmethod
    def get_client_scopes(
        scope_endpoint: str, client_id: str, *, timeout: float = _DEFAULT_TIMEOUT
    ) -> list[str]:
        """Fetch the scopes registered for a client from {base}/api/ClientScopes.

        The endpoint returns [] for an unknown client. A non-200 status or a body
        that is not a JSON array of strings raises — an empty list is a meaningful
        answer, so a failed lookup must never degrade to one.
        """
        sep = "&" if "?" in scope_endpoint else "?"
        url = f"{scope_endpoint}{sep}clientId={quote(client_id, safe='')}"
        resp = _http.request("GET", url, timeout=timeout)
        if resp.status != 200:
            raise OAuthError(
                f"ClientScopes endpoint {resp.status}: {_truncate(resp.text)}", status=resp.status
            )
        try:
            data = json.loads(resp.text)
        except ValueError:
            data = None
        if not isinstance(data, list) or any(not isinstance(s, str) for s in data):
            raise OAuthError(
                "ClientScopes endpoint returned an unexpected body "
                f"(expected a JSON array of strings): {_truncate(resp.text)}",
                status=resp.status,
            )
        return data

    def sign_in(
        self,
        *,
        select_workspace: WorkspaceSelection = WorkspaceSelection.NONE,
        timeout: float = _SIGN_IN_TIMEOUT,
    ) -> TokenSet:
        """Perform interactive PKCE sign-in via ActionWait (public/desktop clients).

        Opens the browser, long-polls for the code callback, verifies state (CSRF),
        exchanges the code, and returns the tokens. Storage is the caller's concern.
        """
        wait_token = str(uuid.uuid4())
        req = self.create_authorization_url(state=wait_token, select_workspace=select_workspace)
        self._open_browser(req.url)
        code = self._poll_action_wait(self._endpoints.action_wait_endpoint, wait_token, timeout)
        return self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._endpoints.redirect_uri,
                "code_verifier": req.code_verifier,
            },
            _DEFAULT_TIMEOUT,
        )

    def _apply_client_auth(self, body: dict[str, str], headers: dict[str, str]) -> None:
        if self._config.client_secret:
            raw = f"{self._config.client_id}:{self._config.client_secret}".encode()
            headers["Authorization"] = f"Basic {b64encode(raw).decode('ascii')}"
        else:
            body["client_id"] = self._config.client_id

    def _token_request(self, params: dict[str, str], timeout: float) -> TokenSet:
        body = dict(params)
        headers = dict(_FORM_HEADERS)
        if self._config.use_secure:
            body["secure"] = "1"
        self._apply_client_auth(body, headers)
        resp = _http.request(
            "POST",
            self._endpoints.token_endpoint,
            headers=headers,
            data=urlencode(body).encode(),
            timeout=timeout,
        )
        if resp.status not in (200, 201):
            error = ""
            desc = ""
            try:
                parsed = json.loads(resp.text)
                if isinstance(parsed, dict):
                    error = parsed.get("error") or ""
                    desc = parsed.get("error_description") or ""
                    error = error if isinstance(error, str) else ""
                    desc = desc if isinstance(desc, str) else ""
            except ValueError:
                pass
            suffix = f" — {desc}" if desc else ""
            raise OAuthError(
                f"Token endpoint {resp.status} {error}{suffix} (body: {_truncate(resp.text)})",
                status=resp.status,
                error=error,
                error_description=desc,
            )
        try:
            parsed = json.loads(resp.text)
        except ValueError:
            raise OAuthError(
                f"Token endpoint returned non-JSON body: {_truncate(resp.text)}", status=resp.status
            ) from None
        if not isinstance(parsed, dict):
            raise OAuthError(
                f"Token endpoint returned non-JSON body: {_truncate(resp.text)}", status=resp.status
            )
        return TokenSet.from_dict(parsed)

    def _poll_action_wait(self, endpoint: str, wait_token: str, timeout: float) -> str:
        """Long-poll ActionWait; return the code once state matches the wait token."""
        start = time.monotonic()
        payload = json.dumps({"token": wait_token}).encode()
        for _ in range(_MAX_RECONNECTS):
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                raise ActionWaitError(f"ActionWait poll timed out after {timeout}s.")
            try:
                resp = _http.request(
                    "POST", endpoint, headers=dict(_JSON_HEADERS), data=payload, timeout=remaining
                )
            except TlsError as exc:
                raise ActionWaitError(f"ActionWait TLS error: {exc}") from exc
            except TransportError:
                if time.monotonic() - start < timeout:
                    raise
                continue
            if resp.status == 408:
                continue
            if resp.status == 410:
                raise ActionWaitError("Sign-in cancelled.")
            if resp.status == 200:
                try:
                    parsed = json.loads(resp.text)
                except ValueError:
                    raise ActionWaitError(
                        f"ActionWait returned 200 but body is not JSON: {_truncate(resp.text)}"
                    ) from None
                data = parsed.get("data") if isinstance(parsed, dict) else None
                if isinstance(data, dict) and isinstance(data.get("error"), str) and data["error"]:
                    desc = data.get("error_description")
                    suffix = f" — {desc}" if isinstance(desc, str) and desc else ""
                    raise ActionWaitError(f"ActionWait sign-in failed: {data['error']}{suffix}")
                code = data.get("code") if isinstance(data, dict) else None
                state = data.get("state") if isinstance(data, dict) else None
                if not isinstance(code, str) or not code:
                    raise ActionWaitError(
                        "ActionWait returned 200 but body is missing data.code: "
                        + _truncate(resp.text)
                    )
                if not isinstance(state, str) or not state:
                    raise ActionWaitError(
                        "ActionWait returned 200 but body is missing data.state: "
                        + _truncate(resp.text)
                    )
                if state != wait_token:
                    raise StateMismatchError(
                        "State mismatch during sign-in (possible CSRF attack)."
                    )
                return code
            raise ActionWaitError(f"ActionWait returned {resp.status}: {_truncate(resp.text)}")
        raise ActionWaitError(f"ActionWait retry count exceeded {_MAX_RECONNECTS}.")

    def _open_browser(self, url: str) -> None:
        try:
            if self._config.open_browser is not None:
                self._config.open_browser(url)
            else:
                webbrowser.open(url)
        except Exception:
            logger.debug("failed to open browser automatically", exc_info=True)
        print(f"\nOpen the following URL in your browser to sign in:\n{url}")
