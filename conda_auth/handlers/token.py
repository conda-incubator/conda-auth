"""
Token implementation for the conda auth handler plugin hook
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace
from string import Formatter

from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase

from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from ..storage import storage
from ..storage.keyring import KeyringStorage
from .base import AuthManager

TOKEN_PARAM_NAME: str = "token"
"""
Name of the configuration parameter where token information is stored
"""

TOKEN_HEADER_PARAM_NAME: str = "token_header"
"""
Name of the configuration parameter where token header name information is stored
"""

TOKEN_TEMPLATE_PARAM_NAME: str = "token_template"
"""
Name of the configuration parameter where token header value template information is stored
"""

DEFAULT_TOKEN_HEADER: str = "Authorization"
"""
Default header used for bearer token authentication
"""

DEFAULT_TOKEN_TEMPLATE: str = "Bearer {token}"
"""
Default header value template used for bearer token authentication
"""

HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

USERNAME: str = "token"
"""
Placeholder value for username. This is written to the secret storage backend
"""

TOKEN_NAME: str = "token"
"""
Name used to refer to this authentication handler in configuration
"""


class TokenAuthManager(AuthManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._header_cache: dict[str, tuple[str, str]] = {}

    def _fetch_secret(self, channel: Channel, settings: Mapping[str, object]) -> tuple[str, str]:
        """
        Gets the secrets by checking the keyring and then falling back to interrupting
        the program and asking the user for secret.
        """
        record = self.get_credential_record(channel, settings)
        token_header, token_template = get_token_header_config(settings, record)

        # First try the value we passed in.
        token = settings.get(TOKEN_PARAM_NAME)
        if token is not None and not isinstance(token, str):
            raise CondaAuthError("Token not found")

        if token is None and record is not None:
            token = record.token

        if token is None:
            raise CondaAuthError("Token not found")

        self._header_cache[channel.canonical_name] = (token_header, token_template)
        return USERNAME, token

    def remove_secret(self, channel: Channel, settings: Mapping[str, object]) -> None:
        self.delete_credential_record(channel, settings)

    def get_auth_type(self) -> str:
        return TOKEN_NAME

    def get_config_parameters(self) -> tuple[str, ...]:
        return (TOKEN_PARAM_NAME, TOKEN_HEADER_PARAM_NAME, TOKEN_TEMPLATE_PARAM_NAME)

    def get_auth_class(self) -> type:
        return TokenAuthHandler

    def create_credential_record(
        self,
        channel: Channel,
        username: str,
        secret: str,
        settings: Mapping[str, object] | None = None,
    ) -> CredentialRecord:
        token_header, token_template = get_token_header_config(settings, None)
        return CredentialRecord(
            target=channel.canonical_name,
            auth_type=TOKEN_NAME,
            username=username,
            token=secret,
            token_header=token_header,
            token_template=token_template,
        )

    def migrate_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> CredentialRecord | None:
        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return None

        for legacy_target in self.legacy_credential_targets(channel, target):
            token = backend.get_legacy_password(TOKEN_NAME, legacy_target, USERNAME)
            if token is None:
                continue

            record = self.create_credential_record(channel, USERNAME, token, settings)
            if record.target != target:
                record = replace(record, target=target)
            backend.set_credential(record)
            backend.delete_legacy_password(TOKEN_NAME, legacy_target, USERNAME)
            return record

        return None

    def delete_legacy_credential_record(
        self,
        channel: Channel,
        settings: Mapping[str, object] | None,
        target: str,
    ) -> None:
        backend = storage.backend
        if not isinstance(backend, KeyringStorage):
            return

        for legacy_target in self.legacy_credential_targets(channel, target):
            backend.delete_legacy_password(TOKEN_NAME, legacy_target, USERNAME)

    def get_header_config(self, channel_name: str) -> tuple[str, str]:
        channel = Channel(channel_name)
        if config := self._header_cache.get(channel.canonical_name):
            return config

        settings = self.get_channel_settings(channel)
        record = self.get_credential_record(channel, settings) if settings is not None else None
        config = get_token_header_config(settings, record)
        self._header_cache[channel.canonical_name] = config
        return config

    def cache_clear(self, channel_name: str | None = None) -> None:
        super().cache_clear(channel_name)
        if channel_name is None:
            self._header_cache.clear()
            return

        self._header_cache.pop(channel_name, None)
        self._header_cache.pop(Channel(channel_name).canonical_name, None)


manager = TokenAuthManager()


def get_token_header_config(
    settings: Mapping[str, object] | None,
    record: CredentialRecord | None,
) -> tuple[str, str]:
    header = get_token_header(settings, record)
    template = get_token_template(settings, record)
    validate_token_header(header)
    validate_token_template(template)
    return header, template


def get_token_header(
    settings: Mapping[str, object] | None,
    record: CredentialRecord | None,
) -> str:
    value = settings.get(TOKEN_HEADER_PARAM_NAME) if settings is not None else None
    if value is None and record is not None:
        value = record.token_header
    if value is None:
        return DEFAULT_TOKEN_HEADER
    if not isinstance(value, str):
        raise CondaAuthError("Token header must be text")
    return value


def get_token_template(
    settings: Mapping[str, object] | None,
    record: CredentialRecord | None,
) -> str:
    value = settings.get(TOKEN_TEMPLATE_PARAM_NAME) if settings is not None else None
    if value is None and record is not None:
        value = record.token_template
    if value is None:
        return DEFAULT_TOKEN_TEMPLATE
    if not isinstance(value, str):
        raise CondaAuthError("Token template must be text")
    return value


def validate_token_header(header: str) -> None:
    if not header or not HEADER_NAME_PATTERN.fullmatch(header):
        raise CondaAuthError("Token header must be a valid HTTP header field name")


def validate_token_template(template: str) -> None:
    field_names = [
        field_name for _, field_name, _, _ in Formatter().parse(template) if field_name is not None
    ]
    if "token" not in field_names:
        raise CondaAuthError("Token template must include '{token}'")
    if any(field_name != "token" for field_name in field_names):
        raise CondaAuthError("Token template must only use the '{token}' field")
    try:
        value = template.format(token="token")
    except (IndexError, KeyError, ValueError) as exc:
        raise CondaAuthError(f"Token template is invalid: {exc}") from exc
    if "\r" in value or "\n" in value:
        raise CondaAuthError("Token template must not contain line breaks")


class TokenAuthHandler(ChannelAuthBase):
    """
    Implements token auth that inserts a token as a header for all network request
    in conda for the channel specified on object instantiation.
    """

    def __init__(self, channel_name: str):
        _, self.token = manager.get_secret(channel_name)

        if self.token is None:
            raise CondaAuthError(
                f"Unable to find authorization token for requests with channel {channel_name}"
            )
        self.header, self.template = manager.get_header_config(channel_name)

        super().__init__(channel_name)

    def __call__(self, r):
        if self.header not in r.headers:
            r.headers[self.header] = self.template.format(token=self.token)

        return r
