"""
Basic auth implementation for the conda fetch plugin hook
"""
from __future__ import annotations

from functools import wraps
from getpass import getpass
from threading import local

import keyring
from requests.auth import HTTPBasicAuth

from conda.base.context import context
from conda.exceptions import CondaError
from conda.gateways.connection.session import CondaSessionBase
from conda.plugins import CondaFetch, CondaPreCommand, hookimpl

_CREDENTIALS_CACHE = {}

PLUGIN_NAME = "conda-basic-auth"


def set_channel_user_credentials(channel_name: str, username: str | None) -> tuple[str, str]:
    """
    Set user credentials using a command prompt. Cache this for the running process
    in the module's ``_CREDENTIALS_CACHE`` dictionary.

    :param channel_name: the channel name that these credentials should be associated with
    :param username: username for the basic auth request (optional)
    """
    if _CREDENTIALS_CACHE.get(channel_name) is not None:
        return _CREDENTIALS_CACHE[channel_name]

    keyring_id = f"conda-{PLUGIN_NAME}::{channel_name}"

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
            # TODO: This key needs to be a constant
            if settings.get("fetch_backend") == PLUGIN_NAME:
                username = settings.get("fetch_backend_username")
                set_channel_user_credentials(channel, username)


@hookimpl
def conda_pre_commands():
    yield CondaPreCommand(
        name=f"{PLUGIN_NAME}_collect_credentials",
        action=collect_credentials,
        run_for={"search", "install", "update", "notices", "create"},
    )


#: We do this because the `Session` object which CondaSessionBase is a subclass of
#: is not thread safe.
_SESSION_OBJECT_CACHE = local()


def cache_session(session: type[BasicAuthSession]):
    """
    Provides a caching mechanism for BasicAuthSession objects
    """

    @wraps(session)
    def wrapper(channel_name: str) -> BasicAuthSession:
        if not hasattr(_SESSION_OBJECT_CACHE, "cache"):
            _SESSION_OBJECT_CACHE.cache = {}

        if _SESSION_OBJECT_CACHE.cache.get(channel_name) is None:
            _SESSION_OBJECT_CACHE.cache[channel_name] = BasicAuthSession(
                channel_name=channel_name
            )

        return _SESSION_OBJECT_CACHE.cache[channel_name]

    return wrapper


class BasicAuthSession(CondaSessionBase):
    def __init__(self, channel_name: str | None = None):
        super().__init__()

        # If a channel name was provided, we override the auth property
        if channel_name:
            credentials = _CREDENTIALS_CACHE.get(channel_name)
            if credentials is None:
                raise CondaError(
                    "Unable to find credentials for http basic authentication requests"
                )
            self.auth = HTTPBasicAuth(*credentials)


@hookimpl
def conda_fetch():
    """
    Register our session class
    """
    yield CondaFetch(name=PLUGIN_NAME, session_class=BasicAuthSession)
