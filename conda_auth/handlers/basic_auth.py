"""
Basic auth implementation for the conda auth handler plugin hook
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase
from requests.auth import HTTPBasicAuth

from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from ..storage import storage
from ..storage.keyring import KeyringStorage
from .base import AuthManager

USERNAME_PARAM_NAME: str = "username"
"""
Name of the configuration parameter where username information is stored
"""

PASSWORD_PARAM_NAME: str = "password"
"""
Name of the configuration parameter where password information is stored
"""

HTTP_BASIC_AUTH_NAME: str = "http-basic"
"""
Name used to refer to this authentication handler in configuration
"""


class BasicAuthManager(AuthManager):
    def _fetch_secret(self, channel: Channel, settings: Mapping[str, object]) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for the credentials.
        """
        record = None
        if not all(
            isinstance(settings.get(name), str)
            for name in (USERNAME_PARAM_NAME, PASSWORD_PARAM_NAME)
        ):
            record = self.get_credential_record(channel, settings)
        username = self.get_username(settings, record)
        password = self.get_password(username, settings, record)

        return username, password

    def remove_secret(self, channel: Channel, settings: Mapping[str, object]) -> None:
        self.delete_credential_record(channel, settings)

    def get_auth_type(self) -> str:
        return HTTP_BASIC_AUTH_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return USERNAME_PARAM_NAME, PASSWORD_PARAM_NAME

    def get_username(
        self,
        settings: Mapping[str, object],
        record: CredentialRecord | None = None,
    ) -> str:
        """
        Attempts to find username in settings and falls back to prompting user for it if not found.
        """
        username = settings.get(USERNAME_PARAM_NAME)

        if not isinstance(username, str) and record is not None:
            username = record.username

        if not isinstance(username, str):
            raise CondaAuthError("Username not found")

        return username

    def get_password(
        self,
        username: str,
        settings: Mapping[str, object],
        record: CredentialRecord | None = None,
    ) -> str:
        """
        Attempts to get password and falls back to prompting the user for it if not found.
        """
        # First see if a value has been passed in
        password = settings.get(PASSWORD_PARAM_NAME)
        if password is not None and not isinstance(password, str):
            raise CondaAuthError("Password not found")

        if password is None and record is not None and record.username == username:
            password = record.password

        if password is None:
            raise CondaAuthError("Password not found")

        return password

    def create_credential_record(
        self,
        channel: Channel,
        username: str,
        secret: str,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord:
        return CredentialRecord(
            target=channel.canonical_name,
            auth_type=HTTP_BASIC_AUTH_NAME,
            username=username,
            password=secret,
        )

    def migrate_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> CredentialRecord | None:
        if settings is None:
            return None

        username = settings.get(USERNAME_PARAM_NAME)
        if not isinstance(username, str):
            return None

        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return None

        for legacy_target in self.legacy_credential_targets(channel, target):
            password = backend.get_legacy_password(HTTP_BASIC_AUTH_NAME, legacy_target, username)
            if password is None:
                continue

            record = self.create_credential_record(channel, username, password, settings)
            if record.target != target:
                record = replace(record, target=target)
            backend.set_credential(record)
            backend.delete_legacy_password(HTTP_BASIC_AUTH_NAME, legacy_target, username)
            return record

        return None

    def delete_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> None:
        if settings is None:
            return

        username = settings.get(USERNAME_PARAM_NAME)
        if not isinstance(username, str):
            return

        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return

        for legacy_target in self.legacy_credential_targets(channel, target):
            backend.delete_legacy_password(HTTP_BASIC_AUTH_NAME, legacy_target, username)

    def get_auth_class(self) -> type:
        return BasicAuthHandler


manager = BasicAuthManager()


class BasicAuthHandler(ChannelAuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.

    Some of this has been copied over from ``requests.auth``.
    """

    def __init__(self, channel_name: str):
        super().__init__(channel_name)
        self.username, self.password = manager.get_secret(channel_name)

        if self.username is None or self.password is None:
            raise CondaAuthError(
                f"Unable to find user credentials for requests with channel {channel_name}"
            )
        self._auth = HTTPBasicAuth(self.username, self.password)

    def __eq__(self, other):
        return all(
            (
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            )
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        if "Authorization" in r.headers:
            return r
        return self._auth(r)
