import ssl
import urllib.error

import pytest

from altium_auth import _http
from altium_auth.errors import TlsError, TransportError


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_response_json():
    assert _http.Response(status=200, text='{"a": 1}').json() == {"a": 1}


def test_request_returns_body_on_success(monkeypatch):
    monkeypatch.setattr(
        _http.urllib.request, "urlopen", lambda req, timeout: _FakeResp(200, b'{"ok": true}')
    )
    r = _http.request("GET", "https://x/y")
    assert r.status == 200
    assert r.json() == {"ok": True}


def test_request_returns_body_on_http_error(monkeypatch):
    def _raise(req, timeout):
        raise urllib.error.HTTPError("https://x/y", 400, "Bad", {}, fp=None)

    monkeypatch.setattr(_http.urllib.request, "urlopen", _raise)
    r = _http.request("POST", "https://x/y", data=b"a=1")
    assert r.status == 400  # 4xx returns a Response, does NOT raise


def test_request_raises_transport_error_on_network_failure(monkeypatch):
    def _raise(req, timeout):
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(_http.urllib.request, "urlopen", _raise)
    with pytest.raises(TransportError):
        _http.request("POST", "https://x/y")


def test_request_raises_tls_error_on_certificate_failure(monkeypatch):
    def _raise(req, timeout):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("certificate has expired"))

    monkeypatch.setattr(_http.urllib.request, "urlopen", _raise)
    with pytest.raises(TlsError):
        _http.request("POST", "https://x/y")


def test_request_rejects_non_http_scheme():
    # Defense-in-depth: only http(s) may reach urlopen (covers get_client_scopes,
    # which takes an unvalidated endpoint URL).
    with pytest.raises(TransportError):
        _http.request("GET", "ftp://x/y")


def test_request_sets_product_user_agent(monkeypatch):
    # stdlib urllib's default "Python-urllib/x.y" UA is blocked (403) by Altium's
    # edge WAF; we must send a product UA instead.
    captured = {}

    def fake(req, timeout):
        captured["ua"] = req.get_header("User-agent")
        return _FakeResp(200, b"{}")

    monkeypatch.setattr(_http.urllib.request, "urlopen", fake)
    _http.request("GET", "https://x/y")
    assert captured["ua"] is not None
    assert captured["ua"].startswith("altium-auth-python/")


def test_request_user_agent_is_overridable(monkeypatch):
    captured = {}

    def fake(req, timeout):
        captured["ua"] = req.get_header("User-agent")
        return _FakeResp(200, b"{}")

    monkeypatch.setattr(_http.urllib.request, "urlopen", fake)
    _http.request("GET", "https://x/y", headers={"User-Agent": "custom/9"})
    assert captured["ua"] == "custom/9"
