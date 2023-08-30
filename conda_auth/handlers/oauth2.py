"""
OAuth2 implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

import keyring
from keyring.errors import PasswordDeleteError
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import OAUTH2_NAME, LOGOUT_ERROR_MESSAGE
from ..exceptions import CondaAuthError
from .base import (
    AuthManager,
    CacheChannelAuthBase,
    test_credentials,
    save_credentials,
)

LOGIN_URL_PARAM_NAME = "login_url"
"""
Setting name that appears in ``context.channel_settings``; used to direct user
to correct login screen.
"""

USERNAME = "token"


class OAuth2Manager(AuthManager):
    def get_keyring_id(self, channel_name: str) -> str:
        return f"{OAUTH2_NAME}::{channel_name}"

    @save_credentials
    @test_credentials
    def set_secrets(self, channel: Channel, **kwargs) -> None:
        if self.cache.get(channel.canonical_name) is not None:
            return

        login_url = kwargs.get(LOGIN_URL_PARAM_NAME)

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

        self.cache[channel.canonical_name] = (USERNAME, token)

    def remove_secrets(
        self, channel_obj: Channel, settings: dict[str, str | None]
    ) -> None:
        keyring_id = self.get_keyring_id(channel_obj.canonical_name)

        try:
            keyring.delete_password(keyring_id, USERNAME)
        except PasswordDeleteError as exc:
            raise CondaAuthError(f"{LOGOUT_ERROR_MESSAGE} {exc}")

    def get_auth_type(self) -> str:
        return OAUTH2_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (LOGIN_URL_PARAM_NAME,)


class OAuth2Handler(CacheChannelAuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        if not hasattr(self, "_cache"):
            raise CondaAuthError(
                "Cache not initialized on class; please run `OAuth2Hanlder.set_cache` before using"
            )

        self.token = self._cache.get(channel_name)

        if self.token is None:
            raise CondaError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__(channel_name)

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"

        return request
