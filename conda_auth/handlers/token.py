"""
Token implementation for the conda auth handler plugin hook
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from urllib.parse import urlparse

from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from ..storage import storage
from ..storage.keyring import KeyringStorage
from .base import AuthManager

TOKEN_PARAM_NAME: str = "token"
"""
Name of the configuration parameter where token information is stored
"""

USERNAME: str = "token"
"""
Placeholder value for username; This is written to the secret storage backend
"""

TOKEN_NAME: str = "token"
"""
Name used to refer to this authentication handler in configuration
"""


class TokenAuthManager(AuthManager):
    def _fetch_secret(self, channel: Channel, settings: Mapping[str, object]) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for secret.
        """
        record = self.get_credential_record(channel, settings)

        # First try the value we passed in.
        token = settings.get(TOKEN_PARAM_NAME)
        if token is not None and not isinstance(token, str):
            raise CondaAuthError("Token not found")

        if token is None and record is not None:
            token = record.token

        if token is None:
            raise CondaAuthError("Token not found")

        return USERNAME, token

    def remove_secret(self, channel: Channel, settings: Mapping[str, object]) -> None:
        self.delete_credential_record(channel, settings)

    def get_auth_type(self) -> str:
        return TOKEN_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (TOKEN_PARAM_NAME,)

    def get_auth_class(self) -> type:
        return TokenAuthHandler

    def create_credential_record(
        self,
        channel: Channel,
        username: str,
        secret: str,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord:
        return CredentialRecord(
            target=channel.canonical_name,
            auth_type=TOKEN_NAME,
            username=username,
            token=secret,
        )

    def migrate_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> CredentialRecord | None:
        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return None

        for legacy_target in self.legacy_credential_targets(channel, target):
            token = backend.get_legacy_password(TOKEN_NAME, legacy_target, USERNAME)
            if token is None:
                continue

            record = self.create_credential_record(channel, USERNAME, token, settings)
            if record.target != target:
                record = replace(record, target=target)
            return record

        return None

    def delete_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> None:
        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return

        for legacy_target in self.legacy_credential_targets(channel, target):
            backend.delete_legacy_password(TOKEN_NAME, legacy_target, USERNAME)


manager = TokenAuthManager()


def is_anaconda_dot_org(channel_name: str) -> bool:
    """
    Determines whether the ``channel_name`` is a https://anaconda.org channel
    """
    channel = Channel(channel_name)

    for url in channel.base_urls:
        if url is None:
            continue

        host = urlparse(url).hostname
        if host == "anaconda.org" or (host is not None and host.endswith(".anaconda.org")):
            return True

    return False


class TokenAuthHandler(ChannelAuthBase):
    """
    Implements token auth that inserts a token as a header for all network request
    in conda for the channel specified on object instantiation.

    We make a special exception for anaconda.org and set the Authentication header as:

        Authentication: token <token>

    In all other cases, we use the "bearer" format:

        Authentication: Bearer <token>
    """

    def __init__(self, channel_name: str):
        _, self.token = manager.get_secret(channel_name)
        self.is_anaconda_dot_org = is_anaconda_dot_org(channel_name)

        if self.token is None:
            raise CondaAuthError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__(channel_name)

    def __call__(self, r):
        if self.is_anaconda_dot_org:
            r.headers["Authorization"] = f"token {self.token}"
        else:
            r.headers["Authorization"] = f"Bearer {self.token}"

        return r
