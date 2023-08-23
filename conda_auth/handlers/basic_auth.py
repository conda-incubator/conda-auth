"""
Basic auth implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from getpass import getpass

import keyring
import keyring.errors
from requests.auth import _basic_auth_str  # type: ignore
from conda.exceptions import CondaError

from ..constants import HTTP_BASIC_AUTH_NAME
from ..exceptions import CondaAuthError
from .base import AuthManager, CacheChannelAuthBase

CACHE: dict[str, tuple[str, str]] = {}
"""
Used as a cache for storing credentials while the command runs.
"""

USERNAME_PARAM_NAME = "username"
"""
Setting name that appears in ``context.channel_settings``; This value is optionally
set. If not set, we ask for it via the ``input`` function.
"""


class BasicAuthManager(AuthManager):
    def _get_keyring_id(self, channel_name: str):
        return f"{HTTP_BASIC_AUTH_NAME}::{channel_name}"

    def set_secrets(self, channel_name: str, **kwargs) -> None:
        username = kwargs.get(USERNAME_PARAM_NAME)

        if self.cache.get(channel_name) is not None:
            return

        keyring_id = self._get_keyring_id(channel_name)

        if username is None:
            print(f"Please provide credentials for channel: {channel_name}")
            username = input("Username: ")

        password = keyring.get_password(keyring_id, username)

        if password is None:
            password = getpass()
            # Save to keyring if retrieving password for the first time
            keyring.set_password(keyring_id, username, password)

        self.cache[channel_name] = (username, password)

    def remove_secrets(self, channel_name: str, **kwargs) -> None:
        keyring_id = self._get_keyring_id(channel_name)
        username = kwargs.get(USERNAME_PARAM_NAME)

        try:
            keyring.delete_password(keyring_id, username)
        except keyring.errors.PasswordDeleteError as exc:
            raise CondaAuthError(f"Unable to remove password. {exc}")

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
