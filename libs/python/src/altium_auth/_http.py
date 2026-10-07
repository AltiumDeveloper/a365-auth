"""Minimal blocking HTTP transport over urllib — the single network seam.

Tests and the conformance runner monkeypatch `request` on this module; the
client always calls it module-qualified (`_http.request(...)`) so the patch
takes effect.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.parse import urlparse

from .errors import TlsError, TransportError

try:
    _USER_AGENT = f"altium-auth-python/{version('altium-auth')}"
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    _USER_AGENT = "altium-auth-python"


@dataclass(frozen=True)
class Response:
    """A completed HTTP response (any status). 4xx/5xx are values, not exceptions."""

    status: int
    text: str

    def json(self) -> Any:
        """Parse the body as JSON (raises ValueError on malformed bodies)."""
        return json.loads(self.text)


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 30.0,
) -> Response:
    """Perform a blocking HTTP request.

    Returns a Response for any HTTP status (including 4xx/5xx, needed for the
    ActionWait 408/410 protocol). Only network-level failures raise TransportError.
    """
    # Only http(s) may reach urlopen — hardens against non-web schemes (file:, ftp:, …)
    # reaching the transport, including via get_client_scopes' unvalidated endpoint URL.
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise TransportError(f"unsupported URL scheme {scheme!r} (expected http or https): {url}")
    # Identify the client with a product User-Agent. The stdlib default
    # ("Python-urllib/x.y") is blocked (HTTP 403) by Altium's edge WAF; a product UA
    # passes (the fetch/.NET references implicitly send a non-python UA). Overridable.
    merged = {"User-Agent": _USER_AGENT}
    if headers:
        merged.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=merged)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return Response(status=resp.status, text=resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp is not None else ""
        return Response(status=exc.code, text=body)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            raise TlsError(f"TLS error requesting {url}: {exc.reason}") from exc
        raise TransportError(f"network error requesting {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise TransportError(f"request to {url} timed out after {timeout}s") from exc
