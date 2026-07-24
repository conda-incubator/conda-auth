from __future__ import annotations

from collections.abc import Mapping

from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import PLUGIN_NAME
from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from ..oauth2_client import (
    OAUTH2_NAME,
    OAUTH2_USERNAME,
    OAUTH_CLIENT_ID_PARAM_NAME,
    OAUTH_CLIENT_SECRET_PARAM_NAME,
    OAUTH_FLOW_PARAM_NAME,
    OAUTH_ISSUER_URL_PARAM_NAME,
    OAUTH_REDIRECT_URI_PARAM_NAME,
    OAUTH_SCOPE_PARAM_NAME,
    OAUTH_USER_AGENT_PARAM_NAME,
    OAuthLoginConfig,
    authorization_code_flow,
    device_code_flow,
    discover_oauth_metadata,
    perform_oauth_login,
    refresh_oauth_record,
    revoke_oauth_record,
    scopes_from_value,
    with_target,
)
from .base import AuthManager

__all__ = (
    "OAUTH2_NAME",
    "OAUTH_CLIENT_ID_PARAM_NAME",
    "OAUTH_CLIENT_SECRET_PARAM_NAME",
    "OAUTH_FLOW_PARAM_NAME",
    "OAUTH_ISSUER_URL_PARAM_NAME",
    "OAUTH_REDIRECT_URI_PARAM_NAME",
    "OAUTH_SCOPE_PARAM_NAME",
    "OAUTH_USER_AGENT_PARAM_NAME",
    "OAuth2AuthHandler",
    "OAuth2Manager",
    "OAuthLoginConfig",
    "authorization_code_flow",
    "device_code_flow",
    "discover_oauth_metadata",
    "manager",
    "perform_oauth_login",
    "refresh_oauth_record",
    "revoke_oauth_record",
    "scopes_from_value",
    "with_target",
)


class OAuth2Manager(AuthManager):
    def get_keyring_id(self, channel: Channel) -> str:
        return f"{PLUGIN_NAME}::{OAUTH2_NAME}::{channel.canonical_name}"

    def _fetch_secret(self, channel: Channel, settings: Mapping[str, object]) -> tuple[str, str]:
        record = self.get_credential_record(channel, settings)
        if record is None or record.auth_type != OAUTH2_NAME or record.access_token is None:
            raise CondaAuthError("OAuth credential not found")

        refreshed = refresh_oauth_record(record)
        if refreshed.access_token is None:
            raise CondaAuthError("OAuth credential not found")
        if refreshed != record:
            self.save_credential_record(refreshed)
        self._cache[channel.canonical_name] = (OAUTH2_USERNAME, refreshed.access_token)
        return OAUTH2_USERNAME, refreshed.access_token

    def save_credential_record(self, record: CredentialRecord) -> None:
        from ..storage import storage

        storage.set_credential(record)

    def remove_secret(self, channel: Channel, settings: Mapping[str, object]) -> None:
        record = self.get_credential_record(channel, settings)
        if record is not None:
            revoke_oauth_record(record)
        self.delete_credential_record(channel, settings)

    def get_auth_type(self) -> str:
        return OAUTH2_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (
            OAUTH_ISSUER_URL_PARAM_NAME,
            OAUTH_CLIENT_ID_PARAM_NAME,
            OAUTH_CLIENT_SECRET_PARAM_NAME,
            OAUTH_FLOW_PARAM_NAME,
            OAUTH_SCOPE_PARAM_NAME,
            OAUTH_REDIRECT_URI_PARAM_NAME,
            OAUTH_USER_AGENT_PARAM_NAME,
        )

    def get_auth_class(self) -> type:
        return OAuth2AuthHandler


manager = OAuth2Manager()


class OAuth2AuthHandler(ChannelAuthBase):
    def __init__(self, channel_name: str):
        _, self.access_token = manager.get_secret(channel_name)
        if self.access_token is None:
            raise CondaAuthError(
                f"Unable to find OAuth credential for requests with {channel_name}"
            )
        super().__init__(channel_name)

    def __call__(self, r):
        if "Authorization" not in r.headers:
            r.headers["Authorization"] = f"Bearer {self.access_token}"
        return r
