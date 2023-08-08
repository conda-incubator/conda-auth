"""
Basic auth implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from getpass import getpass

import keyring
from requests.auth import HTTPBasicAuth  # type: ignore

from conda.exceptions import CondaError

from ..constants import HTTP_BASIC_AUTH_NAME
from .base import AuthManager

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
    def set_secrets(self, channel_name: str, **kwargs) -> None:
        username = kwargs.get(USERNAME_PARAM_NAME)

        if self._cache.get(channel_name) is not None:
            return

        keyring_id = f"{HTTP_BASIC_AUTH_NAME}::{channel_name}"

        if username is None:
            print(f"Please provide credentials for channel: {channel_name}")
            username = input("Username: ")

        password = keyring.get_password(keyring_id, username)

        if password is None:
            password = getpass()
            # Save to keyring if retrieving password for the first time
            keyring.set_password(keyring_id, username, password)

        self._cache[channel_name] = (username, password)

    def get_auth_type(self) -> str:
        return HTTP_BASIC_AUTH_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (USERNAME_PARAM_NAME,)


class BasicAuthHandler(HTTPBasicAuth):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        username, password = CACHE.get(channel_name, (None, None))

        if username is None and password is None:
            raise CondaError(
                f"Unable to find user credentials for requests with channel {channel_name}"
            )

        super().__init__(username, password)
