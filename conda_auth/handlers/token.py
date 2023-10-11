"""
Token implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from collections.abc import Mapping

from conda.exceptions import CondaError
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import PLUGIN_NAME
from ..storage import storage
from .base import AuthManager

TOKEN_PARAM_NAME = "token"
"""
Name of the configuration parameter where token information is stored
"""

USERNAME = "token"
"""
Placeholder value for username; This is written to the secret storage backend
"""

TOKEN_NAME = "token"
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
        keyring_id = self.get_keyring_id(channel)
        token = storage.get_password(keyring_id, USERNAME)

        if token is None:
            token = self.get_token(settings)

        return USERNAME, token

    def remove_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> None:
        keyring_id = self.get_keyring_id(channel)

        storage.delete_password(keyring_id, USERNAME)

    def get_auth_type(self) -> str:
        return TOKEN_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (TOKEN_PARAM_NAME,)

    def get_token(self, settings: Mapping[str, str | None]):
        """
        Attempt to first retrieve token from settings and then prompt the user for it.
        """
        token = settings.get(TOKEN_PARAM_NAME)

        if token is None:
            token = self.prompt_token()

        return token

    def prompt_token(self) -> str:
        """
        This can be overriden for classes that do not want to use the built-in function ``input``.
        """
        return input("Token: ")

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
