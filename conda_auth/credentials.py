from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CredentialRecord:
    """
    Structured credential payload stored in the configured credential backend.
    """

    target: str
    """Storage lookup key and scope for the credential."""

    auth_type: str
    """Authentication mechanism that consumes the credential."""

    username: str | None = None
    """Username for HTTP Basic authentication."""

    password: str | None = None
    """Password for HTTP Basic authentication."""

    token: str | None = None
    """Static token used by token authentication."""

    token_header: str | None = None
    """HTTP request header that carries the static token."""

    token_template: str | None = None
    """Format string used to build the token header value."""

    access_token: str | None = None
    """OAuth 2.0 bearer token used for authenticated requests."""

    refresh_token: str | None = None
    """OAuth 2.0 token used to obtain a new access token."""

    expires_at: int | None = None
    """Access token expiration time as a Unix timestamp."""

    token_endpoint: str | None = None
    """OAuth 2.0 endpoint used to refresh an access token."""

    revocation_endpoint: str | None = None
    """OAuth 2.0 endpoint used to revoke tokens on logout."""

    client_id: str | None = None
    """OAuth 2.0 client identifier used for refresh and revocation."""

    issuer_url: str | None = None
    """OAuth 2.0 issuer URL used for discovery and status output."""

    scopes: tuple[str, ...] = ()
    """OAuth 2.0 scopes requested when obtaining the credential."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CredentialRecord:
        scopes = data.get("scopes", ())
        if isinstance(scopes, list):
            scopes = tuple(str(scope) for scope in scopes)
        elif isinstance(scopes, tuple):
            scopes = tuple(str(scope) for scope in scopes)
        else:
            scopes = ()

        return cls(
            target=str(data["target"]),
            auth_type=str(data["auth_type"]),
            username=_optional_str(data.get("username")),
            password=_optional_str(data.get("password")),
            token=_optional_str(data.get("token")),
            token_header=_optional_str(data.get("token_header")),
            token_template=_optional_str(data.get("token_template")),
            access_token=_optional_str(data.get("access_token")),
            refresh_token=_optional_str(data.get("refresh_token")),
            expires_at=_optional_int(data.get("expires_at")),
            token_endpoint=_optional_str(data.get("token_endpoint")),
            revocation_endpoint=_optional_str(data.get("revocation_endpoint")),
            client_id=_optional_str(data.get("client_id")),
            issuer_url=_optional_str(data.get("issuer_url")),
            scopes=scopes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "target": self.target,
                "auth_type": self.auth_type,
                "username": self.username,
                "password": self.password,
                "token": self.token,
                "token_header": self.token_header,
                "token_template": self.token_template,
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "expires_at": self.expires_at,
                "token_endpoint": self.token_endpoint,
                "revocation_endpoint": self.revocation_endpoint,
                "client_id": self.client_id,
                "issuer_url": self.issuer_url,
                "scopes": list(self.scopes),
            }.items()
            if value is not None and value != []
        }

    def to_status_entry(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "target": self.target,
                "auth_type": self.auth_type,
                "username": self.username,
                "issuer_url": self.issuer_url,
                "expires_at": self.expires_at,
            }.items()
            if value is not None
        }


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
