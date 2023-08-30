from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from functools import wraps
from typing import Any

import conda.base.context
import keyring
import requests
from conda.gateways.connection.session import get_session
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..constants import (
    INVALID_CREDENTIALS_ERROR_MESSAGE,
    USERNAME_AND_PASSWORD_NOT_SET_ERROR_MESSAGE,
)
from ..exceptions import CondaAuthError


class AuthManager(ABC):
    """
    Defines an interface for auth handlers to use within plugin
    """

    def __init__(self, context: conda.base.context.Context, cache: dict | None = None):
        """
        Optionally set a cache to use and configuration parameters to retrieve from
        ``conda.base.context.context.channel_settings``.
        """
        self._context = context
        self.cache = {} if cache is None else cache

    def get_action_func(self) -> Callable[[str], None]:
        """Return a callable to be used as the action function for the pre-command plugin hook"""

        def action(command: str):
            for settings in self._context.channel_settings:
                if channel := settings.get("channel"):
                    channel = Channel(channel)
                    # Only attempt to authenticate for actively used channels
                    if channel.canonical_name in self._context.channels:
                        self.authenticate(channel, settings)

        return action

    def authenticate(self, channel: Channel, settings: dict[str, str]) -> None:
        """Used to retrieve credentials and store them on the ``cache`` property"""
        if settings.get("auth") == self.get_auth_type():
            extra_params = {
                param: settings.get(param) for param in self.get_config_parameters()
            }
            self.set_secrets(channel, extra_params)

    @abstractmethod
    def set_secrets(self, channel: Channel, settings: dict[str, str | None]) -> None:
        """Implementations should include routine for fetching and storing secrets"""

    @abstractmethod
    def remove_secrets(self, channel: Channel, settings: dict[str, str | None]) -> None:
        """Implementations should include routine for removing secrets"""

    @abstractmethod
    def get_auth_type(self) -> str:
        """
        Implementation should return a ``str`` which matches the name of the auth handler type in
        conda's configuration.
        """

    @abstractmethod
    def get_config_parameters(self) -> tuple[str, ...]:
        """
        Implementations should return a ``tuple`` of ``str`` which represent the configuration
        values to use in the ``context.channel_settings`` object.
        """

    @abstractmethod
    def get_keyring_id(self, channel_name: str) -> str:
        """
        Implementation should return the keyring id that will be used by the manager classes
        """


class CacheChannelAuthBase(ChannelAuthBase):
    """
    Adds a class instance cache object for storage of authentication information.
    """

    def __init__(self, channel_name: str):
        """
        Makes sure we have initialized the cache object.
        """
        super().__init__(channel_name)

        if not hasattr(self, "_cache"):
            raise CondaAuthError(
                "Cache not initialized on class; please run `BasicAuthHandler.set_cache`"
                " before using"
            )

    @classmethod
    def set_cache(cls, cache: dict[str, Any]) -> None:
        cls._cache = cache


def test_credentials(func):
    """
    Decorator function used to test whether the collected credentials can successfully make a
    request.

    This decorator could be applied to any function which updates the ``AuthManager.cache``
    property.
    """

    @wraps(func)
    def wrapper(self, channel: Channel, *args, **kwargs):
        func(self, channel, *args, **kwargs)

        for url in channel.base_urls:
            session = get_session(url)
            resp = session.head(url)

            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                if exc.response.status_code == requests.codes["unauthorized"]:
                    error_message = INVALID_CREDENTIALS_ERROR_MESSAGE
                else:
                    error_message = str(exc)

                raise CondaAuthError(error_message)

    return wrapper


def save_credentials(func):
    """
    Decorator function used to save credentials to the keyring storage system.

    This decorator could be applied to any function which updates the ``AuthManager.cache``
    property.
    """

    @wraps(func)
    def wrapper(self, channel: Channel, *args, **kwargs):
        func(self, channel, *args, **kwargs)

        username, secret = self.cache.get(channel.canonical_name, (None, None))

        if username is None and secret is None:
            raise CondaAuthError(USERNAME_AND_PASSWORD_NOT_SET_ERROR_MESSAGE)

        keyring.set_password(
            self.get_keyring_id(channel.canonical_name), username, secret
        )

    return wrapper
