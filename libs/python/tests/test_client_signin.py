import json
import time

import pytest

from altium_auth import AltiumAuthClient, AltiumAuthConfig, _http
from altium_auth.errors import ActionWaitError, StateMismatchError, TlsError, TransportError


def _make_client():
    return AltiumAuthClient(
        AltiumAuthConfig(client_id="c", scopes="openid profile", open_browser=lambda url: None)
    )


class _Seq:
    def __init__(self, polls):
        self.polls, self.i = polls, 0

    def __call__(self, method, url, *, headers=None, data=None, timeout=30.0):
        if "actionwait" in url:
            poll = self.polls[min(self.i, len(self.polls) - 1)]
            self.i += 1
            if isinstance(poll, Exception):
                raise poll
            status, body = poll
            if "<echo>" in body:
                body = body.replace("<echo>", json.loads(data.decode())["token"])
            return _http.Response(status=status, text=body)
        return _http.Response(status=200, text='{"access_token": "AT", "token_type": "Bearer"}')


def test_signin_success(monkeypatch):
    monkeypatch.setattr(
        _http, "request", _Seq([(200, '{"data": {"code": "code-1", "state": "<echo>"}}')])
    )
    assert _make_client().sign_in(timeout=2.0).access_token == "AT"


def test_signin_reconnect_then_success(monkeypatch):
    monkeypatch.setattr(
        _http, "request", _Seq([(408, ""), (200, '{"data": {"code": "c", "state": "<echo>"}}')])
    )
    assert _make_client().sign_in(timeout=2.0).access_token == "AT"


def test_signin_410_cancelled(monkeypatch):
    monkeypatch.setattr(_http, "request", _Seq([(410, "")]))
    with pytest.raises(ActionWaitError) as ei:
        _make_client().sign_in(timeout=2.0)
    assert "cancelled" in str(ei.value)


def test_signin_non_json(monkeypatch):
    monkeypatch.setattr(_http, "request", _Seq([(200, "not json")]))
    with pytest.raises(ActionWaitError) as ei:
        _make_client().sign_in(timeout=2.0)
    assert "not JSON" in str(ei.value)


def test_signin_missing_code(monkeypatch):
    monkeypatch.setattr(_http, "request", _Seq([(200, '{"data": {}}')]))
    with pytest.raises(ActionWaitError) as ei:
        _make_client().sign_in(timeout=2.0)
    assert "missing data.code" in str(ei.value)


def test_signin_state_mismatch(monkeypatch):
    monkeypatch.setattr(
        _http, "request", _Seq([(200, '{"data": {"code": "c", "state": "attacker-state"}}')])
    )
    with pytest.raises(StateMismatchError) as ei:
        _make_client().sign_in(timeout=2.0)
    assert "State mismatch" in str(ei.value)


def test_signin_unreachable_network_fails_fast(monkeypatch):
    seq = _Seq([TransportError("Name or service not known")])
    monkeypatch.setattr(_http, "request", seq)
    with pytest.raises(TransportError):
        _make_client().sign_in(timeout=2.0)
    assert seq.i == 1


def test_signin_request_timeout_reports_the_sign_in_timeout(monkeypatch):
    def timed_out(method, url, *, headers=None, data=None, timeout=30.0):
        time.sleep(timeout)
        raise TransportError("timed out")

    monkeypatch.setattr(_http, "request", timed_out)
    with pytest.raises(ActionWaitError, match="poll timed out"):
        _make_client().sign_in(timeout=0.05)


def test_signin_tls_error_fails_fast(monkeypatch):
    seq = _Seq([TlsError("certificate verify failed")])
    monkeypatch.setattr(_http, "request", seq)
    with pytest.raises(ActionWaitError) as ei:
        _make_client().sign_in(timeout=2.0)
    assert "TLS" in str(ei.value)
    assert seq.i == 1
