from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

import conda.base.context


class AuthManager(ABC):
    """
    Defines an interface for auth handlers to use within plugin
    """

    def __init__(self, context: conda.base.context.Context, cache: dict | None = None):
        """
        Optionally set a cache to use and configuration parameters to retrieve from
        ``conda.base.context.context.channel_setts``.
        """
        self._context = context
        self._cache = cache or {}

    def get_action_func(self) -> Callable[[str], None]:
        """Return a callable to be used as the action function for the pre-command plugin hook"""

        def action(command: str):
            print(self._context.channel_settings)
            for settings in self._context.channel_settings:
                if channel := settings.get("channel"):
                    self.authenticate(channel, settings)

        return action

    def authenticate(self, channel_name: str, settings: dict[str, str]) -> None:
        """Used to retrieve credentials and store them on the ``_cache`` property"""
        if settings.get("auth") == self.get_auth_type():
            extra_params = {
                param: settings.get(param) for param in self.get_config_parameters()
            }
            self.set_secrets(channel_name, **extra_params)

    @abstractmethod
    def set_secrets(self, channel_name: str, **kwargs) -> None:
        """Implementations should include routine for fetching and storing secrets"""

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
