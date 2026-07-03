from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from fnmatch import fnmatch

import conda.base.context
from conda.base.context import context as global_context
from conda.models.channel import Channel

from ..storage import storage


class AuthManager(ABC):
    """
    Defines an interface for auth handlers to use within plugin
    """

    def __init__(
        self,
        context: conda.base.context.Context | None = None,
        cache: dict | None = None,
    ):
        """
        Optionally set a cache and context object to use
        """
        self._context = context or global_context
        self._cache = {} if cache is None else cache

    def store(self, channel: Channel, settings: Mapping[str, str | None]) -> str:
        """
        Used to retrieve credentials and store them in the credential store.

        This method returns a "username" because this property could have been retrieved
        via user input while calling ``fetch_secret``.
        """
        extra_params = {param: settings.get(param) for param in self.get_config_parameters()}
        username, secret = self.fetch_secret(channel, extra_params, use_cache=False)

        self.save_credentials(channel, username, secret)

        return username

    def save_credentials(self, channel: Channel, username: str, secret: str) -> None:
        """
        Saves the provided credentials to our credential store.
        """
        storage.set_password(self.get_keyring_id(channel), username, secret)

    def fetch_secret(
        self,
        channel: Channel,
        settings: Mapping[str, str | None],
        *,
        use_cache: bool = True,
    ) -> tuple[str, str]:
        """
        Fetch secrets and handle updating cache.
        """
        if use_cache and (secrets := self._cache.get(channel.canonical_name)):
            return secrets

        secrets = self._fetch_secret(channel, settings)
        self._cache[channel.canonical_name] = secrets

        return secrets

    def get_secret(self, channel_name: str) -> tuple[str | None, str | None]:
        """
        Get the secret for a channel, using the in-process cache when possible.
        """
        channel = Channel(channel_name)
        secrets = self._cache.get(channel.canonical_name)

        if secrets is not None:
            return secrets

        settings = self.get_channel_settings(channel)
        if settings is None:
            return None, None

        return self.fetch_secret(channel, settings)

    def get_channel_settings(self, channel: Channel) -> Mapping[str, str | None] | None:
        """
        Find the auth settings that apply to a channel.
        """
        matched_settings = None
        for settings in self._context.channel_settings:
            if settings.get("auth") != self.get_auth_type():
                continue
            if configured_channel := settings.get("channel"):
                if self.channel_matches(configured_channel, channel):
                    matched_settings = settings

        return matched_settings

    def channel_matches(self, configured_channel: str, channel: Channel) -> bool:
        """
        Match configured channel names using conda's canonical channel names.
        """
        configured_canonical_name = Channel(configured_channel).canonical_name

        return (
            configured_channel == channel.canonical_name
            or configured_canonical_name == channel.canonical_name
            or fnmatch(channel.canonical_name, configured_channel)
            or fnmatch(channel.canonical_name, configured_canonical_name)
        )

    def cache_clear(self, channel_name: str | None = None) -> None:
        """
        Remove the internal cache for the manager object
        """
        if channel_name:
            self._cache.pop(channel_name, None)
        else:
            self._cache.clear()

    @abstractmethod
    def _fetch_secret(
        self, channel: Channel, settings: Mapping[str, str | None]
    ) -> tuple[str, str]:
        """Implementations should include routine for fetching secret"""

    @abstractmethod
    def remove_secret(self, channel: Channel, settings: Mapping[str, str]) -> None:
        """Implementations should include routine for removing secret"""

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
    def get_keyring_id(self, channel: Channel) -> str:
        """
        Implementation should return the keyring id that will be used by the manager classes
        """

    @abstractmethod
    def get_auth_class(self) -> type:
        """
        Returns the authentication class to use (requests.auth.AuthBase subclass) for the given
        authentication manager
        """
