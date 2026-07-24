"""
OAuth 2.0/OIDC implementation for conda auth.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import webbrowser
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from threading import Event, Thread
from typing import TextIO
from urllib.parse import parse_qs, urlsplit

import requests
from conda.models.channel import Channel

from .credentials import CredentialRecord
from .exceptions import CondaAuthError

OAUTH2_NAME = "oauth2"
OAUTH2_USERNAME = "oauth2"
OAUTH_ISSUER_URL_PARAM_NAME = "oauth_issuer_url"
OAUTH_CLIENT_ID_PARAM_NAME = "oauth_client_id"
OAUTH_CLIENT_SECRET_PARAM_NAME = "oauth_client_secret"
OAUTH_FLOW_PARAM_NAME = "oauth_flow"
OAUTH_SCOPE_PARAM_NAME = "oauth_scopes"
OAUTH_REDIRECT_URI_PARAM_NAME = "oauth_redirect_uri"
OAUTH_USER_AGENT_PARAM_NAME = "user_agent"

OAUTH_EXPIRY_SKEW_SECONDS = 300
OAUTH_CALLBACK_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class OAuthLoginConfig:
    issuer_url: str
    client_id: str
    client_secret: str | None = None
    flow: str = "auto"
    scopes: tuple[str, ...] = ()
    redirect_uri: str | None = None
    user_agent: str | None = None
    output_stream: TextIO | None = None

    def __post_init__(self) -> None:
        validate_oauth_endpoint_url(self.issuer_url, "issuer URL")


@dataclass(frozen=True)
class OAuthTokens:
    access_token: str
    refresh_token: str | None = None
    expires_at: int | None = None
    token_endpoint: str | None = None
    revocation_endpoint: str | None = None


class BrowserOpenError(CondaAuthError):
    """Raised when the auth-code flow cannot open a browser."""


@dataclass(frozen=True)
class OAuthMetadata:
    authorization_endpoint: str | None
    token_endpoint: str | None
    device_authorization_endpoint: str | None = None
    revocation_endpoint: str | None = None

    @classmethod
    def from_mapping(cls, metadata: Mapping[str, object]) -> OAuthMetadata:
        oauth_metadata = cls(
            authorization_endpoint=cls.get_url(metadata, "authorization_endpoint"),
            token_endpoint=cls.get_url(metadata, "token_endpoint"),
            device_authorization_endpoint=cls.get_url(metadata, "device_authorization_endpoint"),
            revocation_endpoint=cls.get_url(metadata, "revocation_endpoint"),
        )
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "device_authorization_endpoint",
            "revocation_endpoint",
        ):
            value = getattr(oauth_metadata, key)
            if value is not None:
                validate_oauth_endpoint_url(value, key)
        return oauth_metadata

    @staticmethod
    def get_url(metadata: Mapping[str, object], key: str) -> str | None:
        value = metadata.get(key)
        if isinstance(value, str):
            return value
        return None

    def require(self, key: str) -> str:
        value = getattr(self, key)
        if value is None:
            raise CondaAuthError(f"OAuth discovery metadata did not include {key!r}")
        return value


@dataclass(frozen=True)
class PKCEChallenge:
    verifier: str
    challenge: str

    @classmethod
    def create(cls) -> PKCEChallenge:
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return cls(verifier=verifier, challenge=challenge)


class OAuthCallbackServer:
    def __init__(self, redirect_uri: str | None, output_stream: TextIO | None = None) -> None:
        self.output_stream = output_stream
        if redirect_uri is None:
            self.server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
            self.redirect_uri = f"http://127.0.0.1:{self.server.server_address[1]}/"
            return

        parsed_redirect = urlsplit(redirect_uri)
        redirect_host = parsed_redirect.hostname
        if redirect_host not in {"127.0.0.1", "localhost"} or parsed_redirect.port is None:
            raise CondaAuthError("OAuth redirect URI must use localhost with an explicit port")

        self.server = _CallbackServer((redirect_host, parsed_redirect.port), _CallbackHandler)
        self.redirect_uri = redirect_uri

    def wait_for_authorization_response(self, authorization_url: str, expected_state: str) -> str:
        callback_state = _CallbackState(expected_state=expected_state)
        self.server.callback_state = callback_state
        thread = Thread(target=self.server.serve_forever, daemon=True)
        thread.start()

        try:
            if not webbrowser.open(authorization_url):
                raise BrowserOpenError("Unable to open browser for OAuth login")

            print(f"Opening browser at:\n\n{authorization_url}", file=self.output_stream)
            print("Waiting for authentication in browser...", file=self.output_stream)

            if not callback_state.completed.wait(OAUTH_CALLBACK_TIMEOUT_SECONDS):
                raise CondaAuthError("Timed out waiting for OAuth callback")
        finally:
            self.server.shutdown()

        if callback_state.error is not None:
            raise CondaAuthError(callback_state.error)
        if callback_state.authorization_response is None:
            raise CondaAuthError("OAuth callback did not include an authorization response")
        return callback_state.authorization_response


class OAuthClient:
    def __init__(self, config: OAuthLoginConfig, metadata: Mapping[str, object]) -> None:
        self.config = config
        self.metadata = OAuthMetadata.from_mapping(metadata)

    @classmethod
    def discover(cls, config: OAuthLoginConfig) -> OAuthClient:
        return cls(config, cls.discover_metadata(config))

    @staticmethod
    def discover_metadata(config: OAuthLoginConfig) -> dict[str, object]:
        issuer_url = config.issuer_url.rstrip("/")
        response = requests.get(
            f"{issuer_url}/.well-known/openid-configuration",
            headers=OAuthClient.headers(config.user_agent),
            timeout=30,
        )
        response.raise_for_status()
        metadata = response.json()
        if not isinstance(metadata, dict):
            raise CondaAuthError("OAuth discovery response is invalid")
        return metadata

    def login(self) -> CredentialRecord:
        if self.config.flow == "auth-code":
            tokens = self.authorization_code_flow()
        elif self.config.flow == "device-code":
            tokens = self.device_code_flow()
        elif self.config.flow == "auto":
            try:
                tokens = self.authorization_code_flow()
            except BrowserOpenError:
                tokens = self.device_code_flow()
        else:
            raise CondaAuthError("OAuth flow must be one of: auto, auth-code, device-code")

        if tokens.token_endpoint is None:
            raise CondaAuthError("OAuth token endpoint not found")

        return CredentialRecord(
            target="",
            auth_type=OAUTH2_NAME,
            username=OAUTH2_USERNAME,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_at=tokens.expires_at,
            token_endpoint=tokens.token_endpoint,
            revocation_endpoint=tokens.revocation_endpoint,
            client_id=self.config.client_id,
            issuer_url=self.config.issuer_url,
            scopes=self.config.scopes,
        )

    def authorization_code_flow(self) -> OAuthTokens:
        from authlib.integrations.requests_client import OAuth2Session

        token_endpoint = self.metadata.require("token_endpoint")
        callback = OAuthCallbackServer(self.config.redirect_uri, self.config.output_stream)
        pkce = PKCEChallenge.create()
        client = OAuth2Session(
            self.config.client_id,
            self.config.client_secret,
            scope=" ".join(self.config.scopes),
            redirect_uri=callback.redirect_uri,
        )
        authorization_url, state = client.create_authorization_url(
            self.metadata.require("authorization_endpoint"),
            code_challenge=pkce.challenge,
            code_challenge_method="S256",
        )
        authorization_response = callback.wait_for_authorization_response(
            authorization_url,
            state,
        )

        token = client.fetch_token(
            token_endpoint,
            authorization_response=authorization_response,
            code_verifier=pkce.verifier,
            include_client_id=self.config.client_secret is None,
        )
        return self.tokens_from_response(
            token,
            token_endpoint,
            self.metadata.revocation_endpoint,
        )

    def device_code_flow(self) -> OAuthTokens:
        device_endpoint = self.metadata.device_authorization_endpoint
        if device_endpoint is None:
            raise CondaAuthError("OAuth server does not support device-code flow")

        token_endpoint = self.metadata.require("token_endpoint")
        response = requests.post(
            device_endpoint,
            data={
                "client_id": self.config.client_id,
                "scope": " ".join(self.config.scopes),
            },
            headers=self.headers(self.config.user_agent),
            timeout=30,
        )
        response.raise_for_status()
        device_data = response.json()

        verification_uri = device_data.get("verification_uri_complete") or device_data.get(
            "verification_uri"
        )
        user_code = device_data.get("user_code")
        if verification_uri is None:
            raise CondaAuthError("OAuth device-code response did not include a verification URI")

        print(
            f"Open this URL to authenticate:\n\n{verification_uri}", file=self.config.output_stream
        )
        if user_code:
            print(f"Enter code: {user_code}", file=self.config.output_stream)

        device_code = device_data.get("device_code")
        if not isinstance(device_code, str):
            raise CondaAuthError("OAuth device-code response did not include a device code")

        interval = int(device_data.get("interval", 5))
        expires_in = int(device_data.get("expires_in", 900))
        deadline = time.time() + expires_in

        while time.time() < deadline:
            time.sleep(interval)
            token_response = requests.post(
                token_endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": self.config.client_id,
                },
                headers=self.headers(self.config.user_agent),
                timeout=30,
            )
            if token_response.status_code == 200:
                return self.tokens_from_response(
                    token_response.json(),
                    token_endpoint,
                    self.metadata.revocation_endpoint,
                )

            error = token_response.json().get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise CondaAuthError(f"OAuth device-code flow failed: {error or token_response.text}")

        raise CondaAuthError("Timed out waiting for OAuth device authorization")

    @staticmethod
    def refresh_record(
        record: CredentialRecord,
        user_agent: str | None = None,
    ) -> CredentialRecord:
        if record.auth_type != OAUTH2_NAME or record.expires_at is None:
            return record
        if record.expires_at - int(time.time()) >= OAUTH_EXPIRY_SKEW_SECONDS:
            return record
        if (
            record.refresh_token is None
            or record.token_endpoint is None
            or record.client_id is None
        ):
            return record

        validate_oauth_endpoint_url(record.token_endpoint, "token endpoint")
        response = requests.post(
            record.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": record.refresh_token,
                "client_id": record.client_id,
            },
            headers=OAuthClient.headers(user_agent),
            timeout=30,
        )
        if not response.ok:
            return record

        tokens = OAuthClient.tokens_from_response(
            response.json(),
            record.token_endpoint,
            record.revocation_endpoint,
        )
        return CredentialRecord(
            target=record.target,
            auth_type=OAUTH2_NAME,
            username=OAUTH2_USERNAME,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token or record.refresh_token,
            expires_at=tokens.expires_at,
            token_endpoint=record.token_endpoint,
            revocation_endpoint=record.revocation_endpoint,
            client_id=record.client_id,
            issuer_url=record.issuer_url,
            scopes=record.scopes,
        )

    @staticmethod
    def revoke_record(record: CredentialRecord, user_agent: str | None = None) -> None:
        if record.revocation_endpoint is None:
            return
        token = record.refresh_token or record.access_token
        if token is None:
            return
        try:
            validate_oauth_endpoint_url(record.revocation_endpoint, "revocation endpoint")
        except CondaAuthError:
            return

        requests.post(
            record.revocation_endpoint,
            data={
                "token": token,
                "client_id": record.client_id,
            },
            headers=OAuthClient.headers(user_agent),
            timeout=30,
        )

    @staticmethod
    def tokens_from_response(
        data: Mapping[str, object],
        token_endpoint: str,
        revocation_endpoint: str | None,
    ) -> OAuthTokens:
        access_token = data.get("access_token")
        if not isinstance(access_token, str):
            raise CondaAuthError("OAuth token response did not include an access token")

        expires_at = None
        expires_in = data.get("expires_in")
        if isinstance(expires_in, int):
            expires_at = int(time.time()) + expires_in

        refresh_token = data.get("refresh_token")
        if not isinstance(refresh_token, str):
            refresh_token = None

        return OAuthTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
        )

    @staticmethod
    def headers(user_agent: str | None) -> dict[str, str] | None:
        if user_agent is None:
            return None
        return {"User-Agent": user_agent}


def discover_oauth_metadata(config: OAuthLoginConfig) -> dict[str, object]:
    return OAuthClient.discover_metadata(config)


def perform_oauth_login(config: OAuthLoginConfig) -> CredentialRecord:
    """
    Run the selected OAuth login flow and return a structured credential record.
    """
    return OAuthClient.discover(config).login()


def authorization_code_flow(
    config: OAuthLoginConfig,
    metadata: Mapping[str, object],
) -> OAuthTokens:
    """
    Run OAuth authorization-code flow with PKCE and a localhost callback.
    """
    return OAuthClient(config, metadata).authorization_code_flow()


def device_code_flow(
    config: OAuthLoginConfig,
    metadata: Mapping[str, object],
) -> OAuthTokens:
    """
    Run OAuth device authorization flow.
    """
    return OAuthClient(config, metadata).device_code_flow()


def refresh_oauth_record(
    record: CredentialRecord, user_agent: str | None = None
) -> CredentialRecord:
    """
    Refresh an OAuth access token if it is expired or about to expire.
    """
    return OAuthClient.refresh_record(record, user_agent=user_agent)


def revoke_oauth_record(record: CredentialRecord, user_agent: str | None = None) -> None:
    """
    Revoke OAuth tokens when the server exposes a revocation endpoint.
    """
    OAuthClient.revoke_record(record, user_agent=user_agent)


def with_target(record: CredentialRecord, channel: Channel) -> CredentialRecord:
    return replace(record, target=channel.canonical_name)


def validate_oauth_endpoint_url(url: str, label: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme == "https" and parsed.netloc:
        return
    if parsed.scheme == "http" and is_loopback_host(parsed.hostname):
        return
    raise CondaAuthError(f"OAuth {label} must use HTTPS or loopback HTTP")


def is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class _CallbackState:
    expected_state: str
    authorization_response: str | None = None
    error: str | None = None
    completed: Event = field(default_factory=Event)


class _CallbackServer(HTTPServer):
    callback_state: _CallbackState


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        assert isinstance(server, _CallbackServer)
        state = server.callback_state
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        received_state = query.get("state", [None])[0]
        if received_state != state.expected_state:
            state.error = "OAuth callback state did not match"
        elif "error" in query:
            state.error = query["error"][0]
        else:
            host = self.headers.get("Host", "127.0.0.1")
            state.authorization_response = f"http://{host}{self.path}"

        body = b"Authentication complete. You can close this window."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        state.completed.set()

    def log_message(self, format: str, *args: object) -> None:
        return


def scopes_from_value(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(scope) for scope in value)
    return ()
