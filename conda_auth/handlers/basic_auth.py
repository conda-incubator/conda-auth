"""
Basic auth implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from getpass import getpass

import keyring
from keyring.errors import PasswordDeleteError
from requests.auth import _basic_auth_str  # type: ignore
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import HTTP_BASIC_AUTH_NAME, LOGOUT_ERROR_MESSAGE
from ..exceptions import CondaAuthError
from .base import (
    AuthManager,
    CacheChannelAuthBase,
    test_credentials,
    save_credentials,
)

USERNAME_PARAM_NAME = "username"
"""
Setting name that appears in ``context.channel_settings``; This value is optionally
set. If not set, we ask for it via the ``input`` function.
"""


class BasicAuthManager(AuthManager):
    def get_keyring_id(self, channel_name: str):
        return f"{HTTP_BASIC_AUTH_NAME}::{channel_name}"

    @save_credentials
    @test_credentials
    def set_secrets(self, channel: Channel, settings: dict[str, str]) -> None:
        if self.cache.get(channel.canonical_name) is not None:
            return

        username = settings.get(USERNAME_PARAM_NAME)
        keyring_id = self.get_keyring_id(channel.canonical_name)

        if username is None:
            print(f"Please provide credentials for channel: {channel.canonical_name}")
            username = input("Username: ")

        password = keyring.get_password(keyring_id, username)

        if password is None:
            password = getpass()

        self.cache[channel.canonical_name] = (username, password)

    def remove_secrets(self, channel: Channel, settings: dict[str, str | None]) -> None:
        keyring_id = self.get_keyring_id(channel.canonical_name)
        username = settings.get(USERNAME_PARAM_NAME)

        if username is None:
            print(f"Please provide credentials for channel: {channel.canonical_name}")
            username = input("Username: ")

        try:
            keyring.delete_password(keyring_id, username)
        except PasswordDeleteError as exc:
            raise CondaAuthError(f"{LOGOUT_ERROR_MESSAGE} {exc}")

    def get_auth_type(self) -> str:
        return HTTP_BASIC_AUTH_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (USERNAME_PARAM_NAME,)


class BasicAuthHandler(CacheChannelAuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.

    Some of this has been copied over from ``requests.auth``.
    """

    def __init__(self, channel_name: str):
        super().__init__(channel_name)
        self.username, self.password = self._cache.get(channel_name, (None, None))

        if self.username is None and self.password is None:
            raise CondaError(
                f"Unable to find user credentials for requests with channel {channel_name}"
            )

    def __eq__(self, other):
        return all(
            [
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return r
