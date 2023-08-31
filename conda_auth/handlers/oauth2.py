"""
OAuth2 implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

import keyring
from keyring.errors import PasswordDeleteError
from conda.base.context import context
from conda.exceptions import CondaError
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import OAUTH2_NAME, LOGOUT_ERROR_MESSAGE
from ..exceptions import CondaAuthError
from .base import AuthManager

LOGIN_URL_PARAM_NAME = "login_url"
"""
Setting name that appears in ``context.channel_settings``; used to direct user
to correct login screen.
"""

USERNAME = "token"


class OAuth2Manager(AuthManager):
    def get_keyring_id(self, channel_name: str) -> str:
        return f"{OAUTH2_NAME}::{channel_name}"

    def _fetch_secret(
        self, channel: Channel, settings: dict[str, str | None]
    ) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for secret.
        """
        login_url = settings.get(LOGIN_URL_PARAM_NAME)

        if login_url is None:
            raise CondaAuthError(
                f'`login_url` is not set for channel "{channel.canonical_name}"; '
                "please set this value in `channel_settings` before attempting to use this "
                "channel with the "
                f"{self.get_auth_type()} auth handler."
            )

        keyring_id = self.get_keyring_id(channel.canonical_name)

        token = keyring.get_password(keyring_id, USERNAME)

        if token is None:
            print(f"Follow link to login: {login_url}")
            token = input("Copy and paste login token here: ")

        return USERNAME, token

    def remove_secret(self, channel: Channel, settings: dict[str, str | None]) -> None:
        keyring_id = self.get_keyring_id(channel.canonical_name)

        try:
            keyring.delete_password(keyring_id, USERNAME)
        except PasswordDeleteError as exc:
            raise CondaAuthError(f"{LOGOUT_ERROR_MESSAGE} {exc}")

    def get_auth_type(self) -> str:
        return OAUTH2_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (LOGIN_URL_PARAM_NAME,)


manager = OAuth2Manager(context)


class OAuth2Handler(ChannelAuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        self.token, _ = manager.get_secret(channel_name)

        if self.token is None:
            raise CondaError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__(channel_name)

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"

        return request
