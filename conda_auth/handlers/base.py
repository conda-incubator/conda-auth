from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import replace
from fnmatch import fnmatch
from ipaddress import ip_address
from urllib.parse import urlparse

import conda.base.context
from conda.auxlib.type_coercion import TypeCoercionError, boolify
from conda.base.context import context as global_context
from conda.common.url import urlparse as conda_urlparse
from conda.models.channel import Channel

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from ..storage import storage


def is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False

    if host.lower() == "localhost":
        return True

    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def get_url_host(url: str) -> str | None:
    parsed_url = urlparse(url)
    if parsed_url.hostname is not None:
        return parsed_url.hostname

    host = parsed_url.netloc.rsplit("@", 1)[-1]
    host_without_port, _, port = host.rpartition(":")
    if host.startswith("::1:") and port.isdigit():
        return host_without_port

    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        return host

    if host.count(":") > 1:
        if port.isdigit():
            return host_without_port

    if ":" in host:
        host, _, _ = host.partition(":")

    return host or None


def allows_plaintext_http(settings: Mapping[str, object] | None) -> bool:
    if settings is None:
        return False

    try:
        return boolify(settings.get(AUTH_ALLOW_PLAINTEXT_HTTP_PARAM))
    except TypeCoercionError:
        return False


def validate_secure_channel(
    channel: Channel,
    *,
    allow_plaintext_http: bool = False,
) -> None:
    """
    Prevent credentials from being sent over unsupported transports.
    """
    for url in channel.base_urls:
        if url is None:
            continue

        parsed_url = urlparse(url)
        if parsed_url.scheme == "https":
            continue

        if parsed_url.scheme == "http":
            if allow_plaintext_http or is_loopback_host(get_url_host(url)):
                continue

            raise CondaAuthError(
                "Refusing to use credentials over insecure HTTP channel "
                f"{url!r}. Use HTTPS or localhost."
            )

        raise CondaAuthError(
            "Refusing to use credentials with unsupported channel scheme "
            f"{parsed_url.scheme!r} for {url!r}. Use HTTPS or localhost."
        )


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

    def store(self, channel: Channel, settings: Mapping[str, object]) -> str:
        """
        Used to retrieve credentials and store them in the credential store.

        This method returns a "username" because this property could have been retrieved
        via user input while calling ``fetch_secret``.
        """
        validate_secure_channel(
            channel,
            allow_plaintext_http=allows_plaintext_http(settings),
        )
        extra_params = {param: settings.get(param) for param in self.get_config_parameters()}
        if allows_plaintext_http(settings):
            extra_params[AUTH_ALLOW_PLAINTEXT_HTTP_PARAM] = True
        username, secret = self.fetch_secret(channel, extra_params, use_cache=False)

        self.save_credentials(
            channel,
            username,
            secret,
            allow_plaintext_http=allows_plaintext_http(settings),
            settings=extra_params,
        )

        return username

    def save_credentials(
        self,
        channel: Channel,
        username: str,
        secret: str,
        *,
        allow_plaintext_http: bool = False,
        target: str | None = None,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord:
        """
        Saves the provided credentials to our credential store.
        """
        validate_secure_channel(
            channel,
            allow_plaintext_http=allow_plaintext_http,
        )
        record = self.create_credential_record(channel, username, secret, settings)
        if target is not None:
            record = replace(record, target=target)
        storage.set_credential(record)
        return record

    def create_credential_record(
        self,
        channel: Channel,
        username: str,
        secret: str,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord:
        """
        Build the structured credential payload persisted by this manager.
        """
        return CredentialRecord(
            target=channel.canonical_name,
            auth_type=self.get_auth_type(),
            username=username,
            password=secret,
        )

    def get_credential_target(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None = None,
    ) -> str:
        if settings is not None:
            target = settings.get("auth_target")
            if isinstance(target, str):
                return target
        return channel.canonical_name

    def get_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord | None:
        """
        Return the structured credential record for a channel, if present.
        """
        target = self.get_credential_target(channel, settings)
        record = storage.get_credential(target)
        if record is not None:
            return record

        return self.migrate_legacy_credential_record(channel, settings, target)

    def migrate_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> CredentialRecord | None:
        """
        Migrate a pre-structured keyring entry for a channel, if this manager supports one.
        """
        return None

    def legacy_credential_targets(self, channel: Channel, target: str) -> tuple[str, ...]:
        """
        Return possible pre-structured keyring targets for a channel.
        """
        targets = [target]
        if channel.canonical_name != target:
            targets.append(channel.canonical_name)
        return tuple(targets)

    def delete_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None = None,
    ) -> None:
        """
        Delete the structured credential record for a channel.
        """
        target = self.get_credential_target(channel, settings)
        storage.delete_credential(target)
        self.delete_legacy_credential_record(channel, settings, target)

    def delete_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> None:
        """
        Delete a pre-structured keyring entry for a channel, if this manager supports one.
        """

    def fetch_secret(
        self,
        channel: Channel,
        settings: Mapping[str, object],
        *,
        use_cache: bool = True,
    ) -> tuple[str, str]:
        """
        Fetch secrets and handle updating cache.
        """
        validate_secure_channel(
            channel,
            allow_plaintext_http=allows_plaintext_http(settings),
        )

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
        settings = self.get_channel_settings(channel)

        validate_secure_channel(
            channel,
            allow_plaintext_http=allows_plaintext_http(settings),
        )
        if secrets is not None:
            return secrets

        if settings is None:
            return None, None

        return self.fetch_secret(channel, settings)

    def get_channel_settings(self, channel: Channel) -> Mapping[str, object] | None:
        """
        Find the auth settings that apply to a channel.
        """
        matched_settings = None
        for settings in self._context.channel_settings:
            if settings.get("auth") != self.get_auth_type():
                continue
            if configured_channel := settings.get("channel"):
                if not isinstance(configured_channel, str):
                    continue
                if self.channel_matches(configured_channel, channel):
                    matched_settings = settings

        return matched_settings

    def channel_matches(self, configured_channel: str, channel: Channel) -> bool:
        """
        Match configured channel names the same way conda selects auth handlers.
        """
        if configured_channel == channel.canonical_name:
            return True

        parsed_channel = conda_urlparse(channel.base_url)
        parsed_setting = conda_urlparse(configured_channel)
        if parsed_setting.scheme != parsed_channel.scheme:
            return False

        channel_url = parsed_channel.netloc + parsed_channel.path
        pattern = parsed_setting.netloc + parsed_setting.path
        return fnmatch(channel_url, pattern)

    def cache_clear(self, channel_name: str | None = None) -> None:
        """
        Remove the internal cache for the manager object
        """
        if channel_name:
            self._cache.pop(channel_name, None)
        else:
            self._cache.clear()

    @abstractmethod
    def _fetch_secret(self, channel: Channel, settings: Mapping[str, object]) -> tuple[str, str]:
        """Implementations should include routine for fetching secret"""

    @abstractmethod
    def remove_secret(self, channel: Channel, settings: Mapping[str, object]) -> None:
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
    def get_auth_class(self) -> type:
        """
        Returns the authentication class to use (requests.auth.AuthBase subclass) for the given
        authentication manager
        """
