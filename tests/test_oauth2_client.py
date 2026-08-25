from __future__ import annotations

import base64
import hashlib
import socket
from dataclasses import dataclass, field
from io import StringIO

import pytest
import requests
from conda.models.channel import Channel
from requests.auth import HTTPBasicAuth

import conda_auth.oauth2_client as oauth2_client
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.oauth2_client import (
    BrowserOpenError,
    OAuthCallbackServer,
    OAuthClient,
    OAuthLoginConfig,
    OAuthMetadata,
    OAuthTokens,
    PKCEChallenge,
    authorization_code_flow,
    device_code_flow,
    discover_oauth_metadata,
    is_loopback_host,
    perform_oauth_login,
    refresh_oauth_record,
    revoke_oauth_record,
    scopes_from_value,
    with_target,
)


@dataclass
class FakeResponse:
    body: object
    status_code: int = 200
    text: str = ""
    raise_for_status_calls: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> object:
        return self.body

    def raise_for_status(self) -> None:
        self.raise_for_status_calls += 1
        if not self.ok:
            raise requests.HTTPError(response=self)


@dataclass
class CompletedEvent:
    wait_calls: list[int] = field(default_factory=list)

    def wait(self, timeout: int) -> bool:
        self.wait_calls.append(timeout)
        return True


@dataclass
class CallbackStateWithoutResponse:
    expected_state: str
    redirect_uri: str
    authorization_response: str | None = None
    error: str | None = None
    completed: CompletedEvent = field(default_factory=CompletedEvent)


class RequestsSession:
    """Delegate test HTTP calls to the monkeypatchable requests module."""

    def get(self, *args, **kwargs):
        return oauth2_client.requests.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return oauth2_client.requests.post(*args, **kwargs)


@pytest.fixture(autouse=True)
def conda_session(monkeypatch):
    session = RequestsSession()
    monkeypatch.setattr(oauth2_client, "get_session", lambda url: session)
    return session


def test_oauth_metadata_normalizes_and_requires_endpoints():
    metadata = OAuthMetadata.from_mapping(
        {
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "device_authorization_endpoint": 123,
        }
    )

    assert metadata.authorization_endpoint == "https://idp.example.com/authorize"
    assert metadata.require("token_endpoint") == "https://idp.example.com/token"
    assert metadata.device_authorization_endpoint is None

    with pytest.raises(CondaAuthError, match="device_authorization_endpoint"):
        metadata.require("device_authorization_endpoint")


def test_pkce_challenge_uses_s256(monkeypatch):
    monkeypatch.setattr(oauth2_client.secrets, "token_urlsafe", lambda size: "verifier")

    challenge = PKCEChallenge.create()

    expected = base64.urlsafe_b64encode(hashlib.sha256(b"verifier").digest()).rstrip(b"=").decode()
    assert challenge == PKCEChallenge(verifier="verifier", challenge=expected)


@pytest.mark.parametrize(
    "redirect_uri",
    (
        "https://localhost:8765/callback",
        "http://example.com:8765/callback",
        "http://localhost/callback",
        "http://user@localhost:8765/callback",
        "http://localhost:8765/callback#fragment",
    ),
    ids=("https", "remote-host", "missing-port", "userinfo", "fragment"),
)
def test_callback_server_rejects_invalid_redirect_uris(redirect_uri):
    with pytest.raises(CondaAuthError, match="localhost with an explicit port"):
        OAuthCallbackServer(redirect_uri)


def test_callback_server_accepts_explicit_loopback_redirect():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    redirect_uri = f"http://127.0.0.1:{port}/callback"
    callback = OAuthCallbackServer(redirect_uri)

    try:
        assert callback.redirect_uri == redirect_uri
    finally:
        callback.server.server_close()


def test_callback_server_uses_registered_redirect_origin(monkeypatch):
    output = StringIO()
    callback = OAuthCallbackServer(None, output)

    def open_browser(_authorization_url):
        response = requests.get(
            f"{callback.redirect_uri}?code=code&state=expected",
            headers={"Host": "attacker.example.com"},
            timeout=5,
        )
        assert response.status_code == 200
        return True

    monkeypatch.setattr(oauth2_client.webbrowser, "open", open_browser)

    authorization_response = callback.wait_for_authorization_response(
        "https://idp.example.com/authorize",
        "expected",
    )

    assert authorization_response == f"{callback.redirect_uri}?code=code&state=expected"
    assert "attacker.example.com" not in authorization_response
    assert output.getvalue() == (
        "Opening browser at:\n\nhttps://idp.example.com/authorize\n"
        "Waiting for authentication in browser...\n"
    )


@pytest.mark.parametrize(
    ("callback_path", "message"),
    (
        ("unexpected?code=code&state=expected", "callback path did not match"),
        ("?code=code&state=wrong", "callback state did not match"),
        ("?error=access_denied&state=expected", "access_denied"),
    ),
    ids=("wrong-path", "wrong-state", "provider-error"),
)
def test_callback_server_rejects_invalid_authorization_responses(
    monkeypatch,
    callback_path,
    message,
):
    callback = OAuthCallbackServer(None)

    def open_browser(_authorization_url):
        requests.get(f"{callback.redirect_uri}{callback_path}", timeout=5)
        return True

    monkeypatch.setattr(oauth2_client.webbrowser, "open", open_browser)

    with pytest.raises(CondaAuthError, match=message):
        callback.wait_for_authorization_response(
            "https://idp.example.com/authorize",
            "expected",
        )


def test_callback_server_reports_browser_open_failure(monkeypatch):
    callback = OAuthCallbackServer(None)
    monkeypatch.setattr(oauth2_client.webbrowser, "open", lambda url: False)

    with pytest.raises(BrowserOpenError, match="Unable to open browser"):
        callback.wait_for_authorization_response(
            "https://idp.example.com/authorize",
            "expected",
        )


def test_callback_server_reports_timeout(monkeypatch):
    callback = OAuthCallbackServer(None)
    monkeypatch.setattr(oauth2_client.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(oauth2_client, "OAUTH_CALLBACK_TIMEOUT_SECONDS", 0)

    with pytest.raises(CondaAuthError, match="Timed out waiting"):
        callback.wait_for_authorization_response(
            "https://idp.example.com/authorize",
            "expected",
        )


def test_callback_server_requires_authorization_response(monkeypatch):
    callback = OAuthCallbackServer(None)
    monkeypatch.setattr(oauth2_client.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(oauth2_client, "_CallbackState", CallbackStateWithoutResponse)

    with pytest.raises(CondaAuthError, match="did not include an authorization response"):
        callback.wait_for_authorization_response(
            "https://idp.example.com/authorize",
            "expected",
        )


@pytest.mark.parametrize(
    ("body", "expected_error"),
    (
        (
            {
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/token",
            },
            None,
        ),
        (["invalid"], "discovery response is invalid"),
    ),
    ids=("valid", "invalid"),
)
def test_discover_oauth_metadata(monkeypatch, body, expected_error):
    response = FakeResponse(body)
    calls = []

    def get(url, headers, timeout):
        calls.append((url, headers, timeout))
        return response

    monkeypatch.setattr(oauth2_client.requests, "get", get)
    config = OAuthLoginConfig(
        "https://idp.example.com/",
        "client",
        user_agent="conda-auth-test",
    )

    if expected_error is not None:
        with pytest.raises(CondaAuthError, match=expected_error):
            discover_oauth_metadata(config)
    else:
        assert discover_oauth_metadata(config) == body

    assert calls == [
        (
            "https://idp.example.com/.well-known/openid-configuration",
            {"User-Agent": "conda-auth-test"},
            30,
        )
    ]
    assert response.raise_for_status_calls == 1


@pytest.mark.parametrize(
    ("flow", "auth_result", "expected_calls"),
    (
        ("auth-code", OAuthTokens("access", token_endpoint="https://idp/token"), ["auth"]),
        ("device-code", OAuthTokens("access", token_endpoint="https://idp/token"), ["device"]),
        ("auto", OAuthTokens("access", token_endpoint="https://idp/token"), ["auth"]),
        ("auto", BrowserOpenError("no browser"), ["auth", "device"]),
    ),
    ids=("auth-code", "device-code", "auto-auth-code", "auto-device-fallback"),
)
def test_oauth_client_login_selects_flow(monkeypatch, flow, auth_result, expected_calls):
    calls = []
    device_result = OAuthTokens(
        "device-access",
        refresh_token="refresh",
        expires_at=100,
        token_endpoint="https://idp/token",
        revocation_endpoint="https://idp/revoke",
    )

    def auth_code(client):
        calls.append("auth")
        if isinstance(auth_result, Exception):
            raise auth_result
        return auth_result

    def device_code(client):
        calls.append("device")
        return device_result

    monkeypatch.setattr(OAuthClient, "authorization_code_flow", auth_code)
    monkeypatch.setattr(OAuthClient, "device_code_flow", device_code)
    config = OAuthLoginConfig(
        "https://idp.example.com",
        "client",
        client_secret="secret",
        flow=flow,
        scopes=("openid",),
    )

    record = OAuthClient(config, {}).login()

    assert calls == expected_calls
    assert record.auth_type == "oauth2"
    assert record.client_id == "client"
    assert record.client_secret == "secret"
    assert record.issuer_url == "https://idp.example.com"
    assert record.scopes == ("openid",)
    if expected_calls[-1] == "device":
        assert record.access_token == "device-access"
        assert record.refresh_token == "refresh"
    else:
        assert record.access_token == "access"


@pytest.mark.parametrize(
    ("flow", "tokens", "message"),
    (
        ("password", OAuthTokens("access", token_endpoint="https://idp/token"), "must be one of"),
        ("auth-code", OAuthTokens("access"), "token endpoint not found"),
    ),
    ids=("invalid-flow", "missing-token-endpoint"),
)
def test_oauth_client_login_rejects_invalid_results(monkeypatch, flow, tokens, message):
    monkeypatch.setattr(OAuthClient, "authorization_code_flow", lambda client: tokens)
    client = OAuthClient(OAuthLoginConfig("https://idp.example.com", "client", flow=flow), {})

    with pytest.raises(CondaAuthError, match=message):
        client.login()


@pytest.mark.parametrize("client_secret", (None, "secret"), ids=("public", "confidential"))
def test_authorization_code_flow_uses_pkce(monkeypatch, conda_session, client_secret):
    calls = []

    class FakeCallback:
        def __init__(self, redirect_uri, output_stream):
            calls.append(("callback", redirect_uri, output_stream))
            self.redirect_uri = "http://127.0.0.1:8765/callback"

        def wait_for_authorization_response(self, authorization_url, state):
            calls.append(("wait", authorization_url, state))
            return f"{self.redirect_uri}?code=code&state={state}"

    class FakeOAuth2Session:
        def __init__(self, session, client_id, client_secret, scope, redirect_uri):
            calls.append(("session", session, client_id, client_secret, scope, redirect_uri))

        def create_authorization_url(self, url, **kwargs):
            calls.append(("authorize", url, kwargs))
            return "https://idp.example.com/authorize?state=state", "state"

        def fetch_token(self, url, **kwargs):
            calls.append(("token", url, kwargs))
            return {"access_token": "access", "refresh_token": "refresh"}

    monkeypatch.setattr(oauth2_client, "OAuthCallbackServer", FakeCallback)
    monkeypatch.setattr(
        oauth2_client.PKCEChallenge,
        "create",
        classmethod(lambda cls: PKCEChallenge("verifier", "challenge")),
    )
    monkeypatch.setattr(
        oauth2_client,
        "CondaOAuth2Client",
        FakeOAuth2Session,
    )
    config = OAuthLoginConfig(
        "https://idp.example.com",
        "client",
        client_secret=client_secret,
        scopes=("openid", "offline_access"),
        redirect_uri="http://localhost:8765/callback",
    )
    metadata = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "revocation_endpoint": "https://idp.example.com/revoke",
    }

    tokens = authorization_code_flow(config, metadata)

    assert tokens == OAuthTokens(
        access_token="access",
        refresh_token="refresh",
        token_endpoint="https://idp.example.com/token",
        revocation_endpoint="https://idp.example.com/revoke",
    )
    assert (
        "session",
        conda_session,
        "client",
        client_secret,
        "openid offline_access",
        "http://127.0.0.1:8765/callback",
    ) in calls
    token_call = next(call for call in calls if call[0] == "token")
    assert token_call[2]["code_verifier"] == "verifier"
    assert token_call[2]["include_client_id"] is (client_secret is None)


def test_device_code_flow_polls_until_authorized(monkeypatch):
    responses = [
        FakeResponse(
            {
                "verification_uri": "https://idp.example.com/device",
                "user_code": "ABCD",
                "device_code": "device",
                "interval": 1,
                "expires_in": 60,
            }
        ),
        FakeResponse({"error": "authorization_pending"}, status_code=400),
        FakeResponse({"error": "slow_down"}, status_code=400),
        FakeResponse(
            {"access_token": "access", "refresh_token": "refresh"},
            status_code=200,
        ),
    ]
    calls = []
    sleeps = []
    output = StringIO()

    def post(url, data, headers, timeout):
        calls.append((url, data, headers, timeout))
        return responses.pop(0)

    monkeypatch.setattr(oauth2_client.requests, "post", post)
    monkeypatch.setattr(oauth2_client.time, "time", lambda: 100)
    monkeypatch.setattr(oauth2_client.time, "sleep", sleeps.append)
    config = OAuthLoginConfig(
        "https://idp.example.com",
        "client",
        flow="device-code",
        scopes=("openid",),
        user_agent="conda-auth-test",
        output_stream=output,
    )
    metadata = {
        "token_endpoint": "https://idp.example.com/token",
        "device_authorization_endpoint": "https://idp.example.com/device",
        "revocation_endpoint": "https://idp.example.com/revoke",
    }

    tokens = device_code_flow(config, metadata)

    assert tokens == OAuthTokens(
        access_token="access",
        refresh_token="refresh",
        token_endpoint="https://idp.example.com/token",
        revocation_endpoint="https://idp.example.com/revoke",
    )
    assert sleeps == [1, 1, 6]
    assert calls[0][1] == {"client_id": "client", "scope": "openid"}
    assert calls[-1][1]["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert output.getvalue() == (
        "Open this URL to authenticate:\n\nhttps://idp.example.com/device\nEnter code: ABCD\n"
    )


@pytest.mark.parametrize(
    ("metadata", "device_data", "expires_in", "message"),
    (
        ({"token_endpoint": "https://idp/token"}, None, None, "does not support"),
        (
            {
                "token_endpoint": "https://idp/token",
                "device_authorization_endpoint": "https://idp/device",
            },
            {"device_code": "device"},
            None,
            "verification URI",
        ),
        (
            {
                "token_endpoint": "https://idp/token",
                "device_authorization_endpoint": "https://idp/device",
            },
            {"verification_uri_complete": "https://idp/verify"},
            None,
            "device code",
        ),
        (
            {
                "token_endpoint": "https://idp/token",
                "device_authorization_endpoint": "https://idp/device",
            },
            {
                "verification_uri": "https://idp/verify",
                "device_code": "device",
                "expires_in": 0,
            },
            0,
            "Timed out",
        ),
    ),
    ids=("unsupported", "missing-verification", "missing-code", "timeout"),
)
def test_device_code_flow_rejects_invalid_responses(
    monkeypatch,
    metadata,
    device_data,
    expires_in,
    message,
):
    if device_data is not None:
        monkeypatch.setattr(
            oauth2_client.requests,
            "post",
            lambda url, data, headers, timeout: FakeResponse(device_data),
        )
    monkeypatch.setattr(oauth2_client.time, "time", lambda: 100)
    monkeypatch.setattr(oauth2_client.time, "sleep", lambda interval: None)
    config = OAuthLoginConfig("https://idp.example.com", "client", flow="device-code")

    with pytest.raises(CondaAuthError, match=message):
        device_code_flow(config, metadata)


def test_device_code_flow_reports_provider_error(monkeypatch):
    responses = [
        FakeResponse(
            {
                "verification_uri": "https://idp/verify",
                "device_code": "device",
                "interval": 0,
            }
        ),
        FakeResponse({}, status_code=400, text="provider failure"),
    ]
    monkeypatch.setattr(
        oauth2_client.requests,
        "post",
        lambda url, data, headers, timeout: responses.pop(0),
    )
    monkeypatch.setattr(oauth2_client.time, "time", lambda: 100)
    monkeypatch.setattr(oauth2_client.time, "sleep", lambda interval: None)
    metadata = {
        "token_endpoint": "https://idp/token",
        "device_authorization_endpoint": "https://idp/device",
    }

    with pytest.raises(CondaAuthError, match="provider failure"):
        device_code_flow(
            OAuthLoginConfig("https://idp.example.com", "client", flow="device-code"),
            metadata,
        )


@pytest.mark.parametrize(
    "record",
    (
        CredentialRecord("target", "token", expires_at=0),
        CredentialRecord("target", "oauth2"),
        CredentialRecord("target", "oauth2", expires_at=10_000),
        CredentialRecord("target", "oauth2", expires_at=0, token_endpoint="https://idp/token"),
        CredentialRecord("target", "oauth2", expires_at=0, refresh_token="refresh"),
        CredentialRecord(
            "target",
            "oauth2",
            expires_at=0,
            refresh_token="refresh",
            token_endpoint="https://idp/token",
        ),
    ),
    ids=(
        "wrong-auth-type",
        "missing-expiry",
        "not-expiring",
        "missing-refresh-token",
        "missing-token-endpoint",
        "missing-client-id",
    ),
)
def test_refresh_record_skips_ineligible_credentials(monkeypatch, record):
    def unexpected_post(*args, **kwargs):
        raise AssertionError("unexpected refresh request")

    monkeypatch.setattr(oauth2_client.time, "time", lambda: 1_000)
    monkeypatch.setattr(oauth2_client.requests, "post", unexpected_post)

    assert refresh_oauth_record(record) is record


@pytest.mark.parametrize(
    ("client_secret", "response", "expected_refresh_token"),
    (
        (None, FakeResponse({"access_token": "new", "expires_in": 3600}), "old-refresh"),
        (
            "secret",
            FakeResponse(
                {
                    "access_token": "new",
                    "refresh_token": "new-refresh",
                    "expires_in": 3600,
                }
            ),
            "new-refresh",
        ),
    ),
    ids=("public-client", "confidential-client"),
)
def test_refresh_record_updates_tokens(
    monkeypatch,
    client_secret,
    response,
    expected_refresh_token,
):
    calls = []

    def post(url, data, auth, headers, timeout):
        calls.append((url, data, auth, headers, timeout))
        return response

    monkeypatch.setattr(oauth2_client.requests, "post", post)
    monkeypatch.setattr(oauth2_client.time, "time", lambda: 1_000)
    record = CredentialRecord(
        target="target",
        auth_type="oauth2",
        access_token="old",
        refresh_token="old-refresh",
        expires_at=999,
        token_endpoint="https://idp.example.com/token",
        revocation_endpoint="https://idp.example.com/revoke",
        client_id="client",
        client_secret=client_secret,
        issuer_url="https://idp.example.com",
        scopes=("openid",),
    )

    refreshed = refresh_oauth_record(record, user_agent="conda-auth-test")

    assert refreshed.access_token == "new"
    assert refreshed.refresh_token == expected_refresh_token
    assert refreshed.expires_at == 4_600
    assert refreshed.client_secret == client_secret
    _, data, auth, headers, timeout = calls[0]
    assert data["grant_type"] == "refresh_token"
    assert headers == {"User-Agent": "conda-auth-test"}
    assert timeout == 30
    if client_secret is None:
        assert data["client_id"] == "client"
        assert auth is None
    else:
        assert "client_id" not in data
        assert isinstance(auth, HTTPBasicAuth)
        assert auth.username == "client"
        assert auth.password == "secret"


def test_refresh_record_keeps_credentials_after_http_failure(monkeypatch):
    record = CredentialRecord(
        target="target",
        auth_type="oauth2",
        access_token="old",
        refresh_token="refresh",
        expires_at=0,
        token_endpoint="https://idp.example.com/token",
        client_id="client",
    )
    monkeypatch.setattr(
        oauth2_client.requests,
        "post",
        lambda *args, **kwargs: FakeResponse({}, status_code=401),
    )

    assert refresh_oauth_record(record) is record


@pytest.mark.parametrize(
    "record",
    (
        CredentialRecord("target", "oauth2", access_token="access"),
        CredentialRecord(
            "target",
            "oauth2",
            revocation_endpoint="https://idp.example.com/revoke",
        ),
        CredentialRecord(
            "target",
            "oauth2",
            access_token="access",
            revocation_endpoint="http://idp.example.com/revoke",
        ),
    ),
    ids=("missing-endpoint", "missing-token", "insecure-endpoint"),
)
def test_revoke_record_skips_ineligible_credentials(monkeypatch, record):
    def unexpected_post(*args, **kwargs):
        raise AssertionError("unexpected revocation request")

    monkeypatch.setattr(oauth2_client.requests, "post", unexpected_post)

    revoke_oauth_record(record)


@pytest.mark.parametrize("client_secret", (None, "secret"), ids=("public", "confidential"))
def test_revoke_record_uses_refresh_token_and_client_auth(monkeypatch, client_secret):
    calls = []

    def post(url, data, auth, headers, timeout):
        calls.append((url, data, auth, headers, timeout))
        return FakeResponse({})

    monkeypatch.setattr(oauth2_client.requests, "post", post)
    record = CredentialRecord(
        target="target",
        auth_type="oauth2",
        access_token="access",
        refresh_token="refresh",
        revocation_endpoint="https://idp.example.com/revoke",
        client_id="client",
        client_secret=client_secret,
    )

    revoke_oauth_record(record, user_agent="conda-auth-test")

    _, data, auth, headers, timeout = calls[0]
    assert data["token"] == "refresh"
    assert headers == {"User-Agent": "conda-auth-test"}
    assert timeout == 30
    if client_secret is None:
        assert data["client_id"] == "client"
        assert auth is None
    else:
        assert "client_id" not in data
        assert isinstance(auth, HTTPBasicAuth)


def test_revoke_record_ignores_network_failure(monkeypatch):
    def post(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(oauth2_client.requests, "post", post)
    record = CredentialRecord(
        target="target",
        auth_type="oauth2",
        access_token="access",
        revocation_endpoint="https://idp.example.com/revoke",
        client_id="client",
    )

    revoke_oauth_record(record)


@pytest.mark.parametrize(
    ("data", "expected"),
    (
        (
            {"access_token": "access", "refresh_token": "refresh", "expires_in": 60},
            OAuthTokens(
                "access",
                refresh_token="refresh",
                expires_at=1_060,
                token_endpoint="https://idp/token",
                revocation_endpoint="https://idp/revoke",
            ),
        ),
        (
            {"access_token": "access", "refresh_token": 123, "expires_in": "60"},
            OAuthTokens(
                "access",
                token_endpoint="https://idp/token",
                revocation_endpoint="https://idp/revoke",
            ),
        ),
    ),
    ids=("complete", "optional-values-invalid"),
)
def test_tokens_from_response(monkeypatch, data, expected):
    monkeypatch.setattr(oauth2_client.time, "time", lambda: 1_000)

    assert (
        OAuthClient.tokens_from_response(
            data,
            "https://idp/token",
            "https://idp/revoke",
        )
        == expected
    )


def test_tokens_from_response_requires_access_token():
    with pytest.raises(CondaAuthError, match="access token"):
        OAuthClient.tokens_from_response({}, "https://idp/token", None)


def test_oauth_wrapper_functions(monkeypatch):
    config = OAuthLoginConfig("https://idp.example.com", "client")
    expected_record = CredentialRecord("target", "oauth2", access_token="access")
    calls = []

    class FakeClient:
        def login(self):
            calls.append("login")
            return expected_record

    monkeypatch.setattr(OAuthClient, "discover", lambda supplied: FakeClient())
    monkeypatch.setattr(
        OAuthClient,
        "refresh_record",
        lambda record, user_agent=None: expected_record,
    )
    monkeypatch.setattr(
        OAuthClient,
        "revoke_record",
        lambda record, user_agent=None: calls.append((record, user_agent)),
    )

    assert perform_oauth_login(config) is expected_record
    assert refresh_oauth_record(expected_record, "agent") is expected_record
    revoke_oauth_record(expected_record, "agent")
    assert calls == ["login", (expected_record, "agent")]


def test_oauth_client_discover_builds_client(monkeypatch):
    config = OAuthLoginConfig("https://idp.example.com", "client")
    metadata = {"token_endpoint": "https://idp.example.com/token"}
    monkeypatch.setattr(OAuthClient, "discover_metadata", lambda supplied: metadata)

    client = OAuthClient.discover(config)

    assert client.config is config
    assert client.metadata.token_endpoint == "https://idp.example.com/token"


def test_with_target_uses_channel_canonical_name():
    record = CredentialRecord("", "oauth2", access_token="access")

    assert with_target(record, Channel("https://repo.example.com/private")).target == (
        "https://repo.example.com/private"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (None, ()),
        ("openid", ("openid",)),
        (["openid", 1], ("openid", "1")),
        (123, ()),
    ),
    ids=("none", "string", "sequence", "invalid"),
)
def test_scopes_from_value(value, expected):
    assert scopes_from_value(value) == expected


@pytest.mark.parametrize(
    ("host", "expected"),
    (
        (None, False),
        ("localhost", True),
        ("127.0.0.1", True),
        ("example.com", False),
    ),
)
def test_is_loopback_host(host, expected):
    assert is_loopback_host(host) is expected
