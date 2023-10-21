"""
Token implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from collections.abc import Mapping

import keyring
from keyring.errors import PasswordDeleteError
from conda.exceptions import CondaError
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import LOGOUT_ERROR_MESSAGE, PLUGIN_NAME
from ..exceptions import CondaAuthError
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
    def get_keyring_id(self, channel: Channel) -> str:
        return f"{PLUGIN_NAME}::{TOKEN_NAME}::{channel.canonical_name}"

    def _fetch_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for secret.
        """
        # First tried the value we passed in
        token = settings.get(TOKEN_PARAM_NAME)

        if token is None:
            # Try password manager if there was nothing there
            keyring_id = self.get_keyring_id(channel)
            token = keyring.get_password(keyring_id, USERNAME)

            if token is None:
                raise CondaAuthError("Token not found")

        return USERNAME, token

    def remove_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> None:
        keyring_id = self.get_keyring_id(channel)

        try:
            keyring.delete_password(keyring_id, USERNAME)
        except PasswordDeleteError as exc:
            raise CondaAuthError(f"{LOGOUT_ERROR_MESSAGE} {exc}")

    def get_auth_type(self) -> str:
        return TOKEN_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (TOKEN_PARAM_NAME,)

    def get_auth_class(self) -> type:
        return TokenAuthHandler


manager = TokenAuthManager()


def is_anaconda_dot_org(channel_name: str) -> bool:
    """
    Determines whether the ``channel_name`` is a https://anaconda.org channel
    """
    channel = Channel(channel_name)
    domain_name = "anaconda.org"

    return any(domain_name in url for url in channel.base_urls)


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
            raise CondaError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__(channel_name)

    def __call__(self, request):
        if self.is_anaconda_dot_org:
            request.headers["Authorization"] = f"token {self.token}"
        else:
            request.headers["Authorization"] = f"Bearer {self.token}"

        return request
