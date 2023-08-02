"""
Basic auth implementation for the conda auth handler plugin hook
"""
from __future__ import annotations

from getpass import getpass

import keyring
from requests.auth import HTTPBasicAuth

from conda.base.context import context
from conda.exceptions import CondaError

from .constants import HTTP_BASIC_AUTH_NAME

_CREDENTIALS_CACHE = {}


def set_channel_user_credentials(channel_name: str, username: str | None) -> None:
    """
    Set user credentials using a command prompt. Cache this for the running process
    in the module's ``_CREDENTIALS_CACHE`` dictionary.

    :param channel_name: the channel name that these credentials should be associated with
    :param username: username for the basic auth request (optional)
    """
    if _CREDENTIALS_CACHE.get(channel_name) is not None:
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

    _CREDENTIALS_CACHE[channel_name] = (username, password)


def collect_credentials(command: str):
    """
    Used to collect user credentials for each channel that is configured to use basic_auth.

    We rely on channel_settings to be correctly configured in order for this to work.
    """
    for settings in context.channel_settings:
        if channel := settings.get("channel"):
            if settings.get("auth") == HTTP_BASIC_AUTH_NAME:
                username = settings.get("username")
                set_channel_user_credentials(channel, username)


class CondaHTTPBasicAuth(HTTPBasicAuth):
    """
    Implementation of HTTPBasicAuth that relies on a cache location for
    retrieving login credentials on object instantiation.
    """

    def __init__(self, channel_name: str):
        username, password = _CREDENTIALS_CACHE.get(channel_name, (None, None))

        if username is None and password is None:
            raise CondaError(
                f"Unable to find user credentials for requests with channel {channel_name}"
            )

        super().__init__(username, password)
