"""
OAuth2 implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

import keyring
from requests.auth import AuthBase
from conda.base.context import context
from conda.exceptions import CondaError

from .constants import OAUTH2_NAME

_TOKEN_CACHE = {}


def set_channel_authorization_token(channel_name: str, login_url: str) -> None:
    """
    Set user credentials using a command prompt. Cache this for the running process
    in the module's ``_CREDENTIALS_CACHE`` dictionary.

    :param channel_name: the channel name that these credentials should be associated with
    :param login_url: URL to use for logging in to channel server

    TODO: We hardcode a "token" username, but later we could use a configured API endpoint
          to retrieve actual user information (e.g. /profile)
    """
    username = "token"

    if _TOKEN_CACHE.get(channel_name) is not None:
        return _TOKEN_CACHE[channel_name]

    keyring_id = f"{OAUTH2_NAME}::{channel_name}"

    token = keyring.get_password(keyring_id, username)

    if token is None:
        print(f"Follow link to login: {login_url}")
        token = input("Copy and paste login token here: ")
        # Save to keyring if retrieving password for the first time
        keyring.set_password(keyring_id, username, token)

    _TOKEN_CACHE[channel_name] = token


def collect_token(command: str):
    """
    Used to collect user credentials for each channel that is configured to use basic_auth.

    We rely on channel_settings to be correctly configured in order for this to work.
    """
    for settings in context.channel_settings:
        if channel := settings.get("channel"):
            if settings.get("auth") == OAUTH2_NAME:
                if login_url := settings.get("login_url"):
                    set_channel_authorization_token(channel, login_url)


class CondaOAuth2(AuthBase):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        self.token = _TOKEN_CACHE.get(channel_name)

        if self.token is None:
            raise CondaError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )

        super().__init__()

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"

        return request
