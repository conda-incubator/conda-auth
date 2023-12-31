"""
Basic auth implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from collections.abc import Mapping

from requests.auth import _basic_auth_str  # type: ignore
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import PLUGIN_NAME
from ..exceptions import CondaAuthError
from ..storage import storage
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
    def get_keyring_id(self, channel: Channel):
        return f"{PLUGIN_NAME}::{HTTP_BASIC_AUTH_NAME}::{channel.canonical_name}"

    def _fetch_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for the credentials.
        """
        username = self.get_username(settings)
        password = self.get_password(username, settings, channel)

        return username, password

    def remove_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> None:
        keyring_id = self.get_keyring_id(channel)
        username = self.get_username(settings)

        storage.delete_password(keyring_id, username)

    def get_auth_type(self) -> str:
        return HTTP_BASIC_AUTH_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return USERNAME_PARAM_NAME, PASSWORD_PARAM_NAME

    def get_username(self, settings: Mapping[str, str | None]):
        """
        Attempts to find username in settings and falls back to prompting user for it if not found.
        """
        username = settings.get(USERNAME_PARAM_NAME)

        if username is None:
            raise CondaAuthError("Username not found")

        return username

    def get_password(
        self, username: str, settings: Mapping[str, str | None], channel: Channel
    ) -> str:
        """
        Attempts to get password and falls back to prompting the user for it if not found.
        """
        # First see if a value has been passed in
        password = settings.get(PASSWORD_PARAM_NAME)

        # Now try retrieving it from the password manager
        if password is None:
            keyring_id = self.get_keyring_id(channel)
            password = storage.get_password(keyring_id, username)

            if password is None:
                raise CondaAuthError("Password not found")

        return password

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

        if self.username is None and self.password is None:
            raise CondaAuthError(
                f"Unable to find user credentials for requests with channel {channel_name}"
            )

    def __eq__(self, other):
        return all(
            (
                self.username == getattr(other, "username", None),
                self.password == getattr(other, "password", None),
            )
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, request):
        request.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return request
