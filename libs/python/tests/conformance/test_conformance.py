"""Conformance runner — drives altium_auth with spec/conformance/vectors.json.

Mirrors libs/typescript/test/conformance and libs/dotnet/tests ConformanceTests:
a single HTTP seam is monkeypatched; each vector asserts the outgoing request and
the outcome. The vectors are the language-neutral source of truth.
"""

from __future__ import annotations

import base64
import json
import pathlib
import time
from urllib.parse import parse_qs, urlparse

import pytest

from altium_auth import (
    COMMERCIAL_CLOUD_ENDPOINTS,
    AltiumAuthClient,
    AltiumAuthConfig,
    AltiumEndpoints,
    WorkspaceSelection,
    _http,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
_VECTORS = json.loads((_REPO_ROOT / "spec" / "conformance" / "vectors.json").read_text())


def _match_string(actual: str | None, matcher: object) -> bool:
    if matcher == "<any>":
        return actual is not None
    if isinstance(matcher, str) and matcher.startswith("contains:"):
        return matcher[len("contains:") :] in (actual or "")
    return actual == matcher


def _mock_body(mock: dict) -> tuple[int, str]:
    status = mock["status"]
    if "json" in mock:
        return status, json.dumps(mock["json"])
    return status, mock.get("text", "")


def _form(body: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


def _build_config(c: dict) -> AltiumAuthConfig:
    d = COMMERCIAL_CLOUD_ENDPOINTS
    endpoints = AltiumEndpoints(
        authorize_endpoint=c.get("authEndpoint", d.authorize_endpoint),
        token_endpoint=c.get("tokenEndpoint", d.token_endpoint),
        action_wait_endpoint=c.get("actionWaitEndpoint", d.action_wait_endpoint),
        redirect_uri=c.get("redirectUri", d.redirect_uri),
    )
    return AltiumAuthConfig(
        client_id=c["clientId"],
        scopes=c.get("scopes", ""),
        client_secret=c.get("clientSecret"),
        endpoints=endpoints,
        open_browser=lambda url: None,
    )


class _Recorder:
    """Fake _http.request: records calls, replies via a responder(url, body, idx)."""

    def __init__(self, responder):
        self.calls: list[dict] = []
        self._responder = responder

    def __call__(self, method, url, *, headers=None, data=None, timeout=30.0):
        body = data.decode() if isinstance(data, (bytes, bytearray)) else (data or "")
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        status, text = self._responder(url, body, len(self.calls) - 1)
        return _http.Response(status=status, text=text)


@pytest.fixture
def install(monkeypatch):
    def _install(responder):
        rec = _Recorder(responder)
        monkeypatch.setattr(_http, "request", rec)
        return rec

    return _install


def _check_request(call: dict, er: dict, config: AltiumAuthConfig) -> None:
    if "endpoint" in er:
        assert call["url"] == er["endpoint"]
    if "method" in er:
        assert call["method"] == er["method"]
    if "authorization" in er:
        auth = call["headers"].get("Authorization")
        if er["authorization"] == "none":
            assert auth is None
        elif er["authorization"].startswith("basic("):
            raw = f"{config.client_id}:{config.client_secret}".encode()
            assert auth == "Basic " + base64.b64encode(raw).decode()
    form = _form(call["body"])
    for k, matcher in er.get("bodyParams", {}).items():
        assert _match_string(form.get(k), matcher), f"bodyParam {k}={form.get(k)!r}"
    for k in er.get("bodyParamsAbsent", []):
        assert k not in form, f"bodyParam {k} should be absent"


@pytest.mark.parametrize("v", _VECTORS["authorizeUrl"], ids=lambda v: v["id"])
def test_authorize_url(v):
    client = AltiumAuthClient(_build_config(v["config"]))
    opts = v["options"]
    sw = (
        WorkspaceSelection(opts["selectWorkspace"])
        if "selectWorkspace" in opts
        else WorkspaceSelection.NONE
    )
    req = client.create_authorization_url(
        redirect_uri=opts.get("redirectUri"),
        state=opts.get("state"),
        code_verifier=opts.get("codeVerifier"),
        select_workspace=sw,
    )
    u = urlparse(req.url)
    q = {k: val[0] for k, val in parse_qs(u.query, keep_blank_values=True).items()}
    expect = v["expect"]
    assert f"{u.scheme}://{u.netloc}" == expect["origin"]
    assert u.path == expect["pathname"]
    for k, matcher in expect.get("query", {}).items():
        assert _match_string(q.get(k), matcher), f"query {k}={q.get(k)!r}"
    for k in expect.get("queryAbsent", []):
        assert k not in q, f"query {k} should be absent"


@pytest.mark.parametrize("v", _VECTORS["tokenRequest"], ids=lambda v: v["id"])
def test_token_request(v, install):
    config = _build_config(v["config"])
    status, text = _mock_body(v["mockResponse"])
    rec = install(lambda url, body, idx: (status, text))
    client = AltiumAuthClient(config)
    inp = v["input"]

    def run():
        op = v["operation"]
        if op == "exchangeCode":
            return client.exchange_code(
                inp["code"],
                code_verifier=inp.get("codeVerifier"),
                redirect_uri=inp.get("redirectUri"),
            )
        if op == "signIntoWorkspace":
            return client.sign_into_workspace(inp["baseAccessToken"], inp["workspaceAuthId"])
        if op == "refreshToken":
            return client.refresh_token(inp["refreshToken"])
        raise AssertionError(f"unknown operation {op}")

    if "expectErrorContains" in v:
        with pytest.raises(Exception) as ei:
            run()
        assert v["expectErrorContains"] in str(ei.value)
    else:
        result = run()
        for k, val in v.get("expectResult", {}).items():
            actual = getattr(result, k)
            if val == "<any>":
                assert actual is not None
            elif isinstance(val, str) and val.startswith("epochWithin:"):
                _, off, tol = val.split(":")
                assert abs(actual - (int(time.time()) + int(off))) <= int(tol)
            else:
                assert actual == val

    assert rec.calls
    _check_request(rec.calls[0], v.get("expectRequest", {}), config)


@pytest.mark.parametrize(
    "v", [x for x in _VECTORS["revocation"] if "expectRequest" in x], ids=lambda v: v["id"]
)
def test_revocation(v, install):
    config = _build_config(v["config"])
    status, text = _mock_body(v["mockResponse"])
    rec = install(lambda url, body, idx: (status, text))
    AltiumAuthClient(config).revoke_refresh_token(v["input"]["refreshToken"])
    assert rec.calls
    _check_request(rec.calls[0], v["expectRequest"], config)


@pytest.mark.parametrize("v", _VECTORS["actionWait"], ids=lambda v: v["id"])
def test_action_wait(v, install):
    polls = v["pollResponses"]
    counter = {"i": 0}

    def responder(url, body, _idx):
        if "actionwait" in url:
            status, text = _mock_body(polls[min(counter["i"], len(polls) - 1)])
            counter["i"] += 1
            if "<stateEchoesToken>" in text:
                text = text.replace("<stateEchoesToken>", json.loads(body)["token"])
            return status, text
        return 200, json.dumps({"access_token": "AT", "token_type": "Bearer"})

    install(responder)
    client = AltiumAuthClient(
        AltiumAuthConfig(client_id="c", scopes="openid profile", open_browser=lambda url: None)
    )
    expect = v["expect"]
    if expect["outcome"] == "code":
        assert client.sign_in(timeout=2.0).access_token == "AT"
    else:
        with pytest.raises(Exception) as ei:
            client.sign_in(timeout=2.0)
        assert expect["errorContains"] in str(ei.value)


@pytest.mark.parametrize("v", _VECTORS["clientScopes"], ids=lambda v: v["id"])
def test_client_scopes(v, install):
    status, text = _mock_body(v["mockResponse"])
    rec = install(lambda url, body, idx: (status, text))
    inp = v["input"]
    if "expectErrorContains" in v:
        with pytest.raises(Exception) as ei:
            AltiumAuthClient.get_client_scopes(inp["scopeEndpoint"], inp["clientId"])
        assert v["expectErrorContains"] in str(ei.value)
    else:
        assert (
            AltiumAuthClient.get_client_scopes(inp["scopeEndpoint"], inp["clientId"])
            == v["expectResult"]
        )
    if "expectRequest" in v:
        assert rec.calls
        er = v["expectRequest"]
        if "endpoint" in er:
            assert rec.calls[0]["url"] == er["endpoint"]
        if "method" in er:
            assert rec.calls[0]["method"] == er["method"]


@pytest.mark.skip(reason="reference response shape — not a library function")
def test_userinfo_reference(): ...


@pytest.mark.skip(reason="golden decoded claims — require a live server")
def test_live_claims_reference(): ...
