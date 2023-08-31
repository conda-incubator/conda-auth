from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

import conda.base.context
import keyring
import requests
from conda.gateways.connection.session import get_session
from conda.models.channel import Channel

from ..exceptions import CondaAuthError

INVALID_CREDENTIALS_ERROR_MESSAGE = "Provided credentials are not correct."


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
        self._cache = {} if cache is None else cache

    def get_action_func(self) -> Callable[[str], None]:
        """Return a callable to be used as the action function for the pre-command plugin hook"""

        def action(command: str):
            for settings in self._context.channel_settings:
                if channel := settings.get("channel"):
                    channel = Channel(channel)
                    # Only attempt to authenticate for actively used channels
                    if (
                        channel.canonical_name in self._context.channels
                        and settings.get("auth") == self.get_auth_type()
                    ):
                        self.authenticate(channel, settings)

        return action

    def authenticate(self, channel: Channel, settings: dict[str, str]) -> None:
        """Used to retrieve credentials and store them on the ``cache`` property"""
        extra_params = {
            param: settings.get(param) for param in self.get_config_parameters()
        }
        username, secret = self.fetch_secret(channel, extra_params)

        verify_credentials(channel)
        self.save_credentials(channel, username, secret)

    def save_credentials(self, channel: Channel, username: str, secret: str) -> None:
        """
        Saves the provided credentials to our credential store.

        TODO: Method may be expanded in the future to allow the use of other storage
              mechanisms.
        """
        keyring.set_password(
            self.get_keyring_id(channel.canonical_name), username, secret
        )

    def fetch_secret(
        self, channel: Channel, settings: dict[str, str | None]
    ) -> tuple[str, str]:
        """
        Fetch secrets and handle updating cache.
        """
        if secrets := self._cache.get(channel.canonical_name):
            return secrets

        secrets = self._fetch_secret(channel, settings)
        self._cache[channel.canonical_name] = secrets

        return secrets

    def get_secret(self, channel_name: str) -> tuple[str | None, str | None]:
        """
        Get the secret that is currently cached for the channel
        """
        secrets = self._cache.get(channel_name)

        if secrets is None:
            return None, None

        return secrets

    @abstractmethod
    def _fetch_secret(
        self, channel: Channel, settings: dict[str, str | None]
    ) -> tuple[str, str]:
        """Implementations should include routine for fetching secret"""

    @abstractmethod
    def remove_secret(self, channel: Channel, settings: dict[str, str | None]) -> None:
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
    def get_keyring_id(self, channel_name: str) -> str:
        """
        Implementation should return the keyring id that will be used by the manager classes
        """


def verify_credentials(channel: Channel) -> None:
    """
    Verify the credentials that have been currently set for the channel.

    Raises exception if unable to make a successful request.
    """
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
