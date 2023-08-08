"""
OAuth2 implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

import keyring
from conda.exceptions import CondaError
from requests.auth import AuthBase  # type: ignore

from ..constants import OAUTH2_NAME
from ..exceptions import CondaAuthError
from .base import AuthManager

CACHE: dict[str, str] = {}
"""
Used as a cache for storing credentials while the command runs.
"""

LOGIN_URL_PARAM_NAME = "login_url"
"""
Setting name that appears in ``context.channel_settings``; used to direct user
to correct login screen.
"""


class OAuth2Manager(AuthManager):
    def set_secrets(self, channel_name: str, **kwargs) -> None:
        login_url = kwargs.get(LOGIN_URL_PARAM_NAME)
        if login_url is None:
            raise CondaAuthError(
                f'`login_url` is not set for channel "{channel_name}"; '
                "please set this value in `channel_settings` before attempting to use this "
                "channel with the "
                f"{self.get_auth_type()} auth handler."
            )
        username = "token"

        if self._cache.get(channel_name) is not None:
            return

        keyring_id = f"{OAUTH2_NAME}::{channel_name}"

        token = keyring.get_password(keyring_id, username)

        if token is None:
            print(f"Follow link to login: {login_url}")
            token = input("Copy and paste login token here: ")
            # Save to keyring if retrieving password for the first time
            keyring.set_password(keyring_id, username, token)

        self._cache[channel_name] = token

    def get_auth_type(self) -> str:
        return OAUTH2_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (LOGIN_URL_PARAM_NAME,)


class OAuth2Handler(AuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        self.token = CACHE.get(channel_name)

        if self.token is None:
            raise CondaError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__()

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"

        return request
