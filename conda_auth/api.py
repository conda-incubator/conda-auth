"""Prepare authentication independently from committing conda configuration."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal, TypedDict

from conda.cli.condarc import ConfigurationFile
from conda.models.channel import Channel

from .exceptions import CondaAuthError


class ChannelSettingsEdit(TypedDict):
    channel: str
    set: dict[str, object]
    unset: list[str]


@dataclass(frozen=True)
class LoginPreparation:
    """Report a configuration edit separately from provider-owned credentials.

    Preparing a login never writes or mutates the selected configuration.
    Credentials may already have been stored by conda-auth. Cancelling the
    configuration edit does not remove those credentials.
    """

    configuration_edit: ChannelSettingsEdit | None
    credentials_state: Literal["stored", "external", "unchanged"]


def plan_channel_settings(
    configuration: ConfigurationFile,
    channel: str,
    auth_type: str,
    *,
    auth_target: str | None = None,
    allow_plaintext_http: bool = False,
    settings: Mapping[str, object] | None = None,
) -> ChannelSettingsEdit:
    """Return auth-owned field edits without changing configuration or credentials.

    The caller supplies a native ConfigurationFile for its chosen user, system,
    environment, or explicit file target. Apply ``set`` and ``unset`` to the last
    exact channel_settings entry, preserving all other entries and fields.
    The caller owns validation, concurrency checks, and the eventual commit.
    """
    from .cli.channel import get_auth_manager
    from .cli.config import (
        AUTH_CHANNEL_SETTING_KEYS,
        AUTH_PUBLIC_CONFIG_KEYS,
        get_updated_channel_settings,
    )

    auth_type, _ = get_auth_manager(auth=auth_type)
    if settings is not None and set(settings) - AUTH_PUBLIC_CONFIG_KEYS:
        raise CondaAuthError("Only public authentication settings can be staged")
    channel_settings = configuration.content.get("channel_settings", []) or []
    if not isinstance(channel_settings, list):
        raise CondaAuthError("Expected 'channel_settings' to be a list")
    previous = next(
        (
            entry
            for entry in reversed(channel_settings)
            if isinstance(entry, Mapping) and entry.get("channel") == channel
        ),
        {},
    )
    updated = get_updated_channel_settings(
        deepcopy(channel_settings),
        channel,
        auth_type,
        auth_target=auth_target,
        allow_plaintext_http=allow_plaintext_http,
        settings=settings,
    )
    selected = next(
        entry
        for entry in reversed(updated)
        if isinstance(entry, Mapping) and entry.get("channel") == channel
    )
    return {
        "channel": channel,
        "set": {key: value for key, value in selected.items() if key in AUTH_CHANNEL_SETTING_KEYS},
        "unset": sorted(
            key for key in previous if key in AUTH_CHANNEL_SETTING_KEYS and key not in selected
        ),
    }


def prepare_login(
    channel: Channel,
    *,
    configuration: ConfigurationFile,
    interactive: bool = False,
    **login_options: object,
) -> LoginPreparation:
    """Authenticate using native login options and return a staged config edit.

    Credential acquisition, storage, optional verification, and OAuth flows are
    the same as ``conda auth login``. This call performs no configuration write.
    Explicit interactive mode prompts for missing basic credentials or a token.
    A caller must not print login_options, which can contain credentials.
    """
    from .cli.channel import _login, get_auth_manager
    from .handlers import HTTP_BASIC_AUTH_NAME, OAUTH2_NAME, TOKEN_NAME

    allowed = {
        "auth",
        "basic",
        "token",
        "token_file",
        "oauth2",
        "username",
        "password",
        "oauth_issuer_url",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_flow",
        "oauth_scopes",
        "oauth_redirect_uri",
        "user_agent",
        "oauth_output_stream",
        "token_header",
        "token_template",
        "auth_allow_plaintext_http",
        "verify",
    }
    if set(login_options) - allowed:
        raise CondaAuthError("Unknown login option")
    methods = [
        HTTP_BASIC_AUTH_NAME if login_options.get("basic") else None,
        TOKEN_NAME if login_options.get("token") is not None else None,
        TOKEN_NAME if login_options.get("token_file") is not None else None,
        OAUTH2_NAME if login_options.get("oauth2") else None,
    ]
    if sum(method is not None for method in methods) > 1:
        raise CondaAuthError("Select one authentication method")
    configured_auth = login_options.get("auth")
    if configured_auth is not None and not isinstance(configured_auth, str):
        raise CondaAuthError("Authentication type must be text")
    for key in ("basic", "oauth2", "auth_allow_plaintext_http", "verify"):
        if login_options.get(key) is not None and not isinstance(login_options[key], bool):
            raise CondaAuthError(f"Login option {key!r} must be a boolean")
    auth_type, _ = get_auth_manager(
        auth=configured_auth or next((method for method in methods if method is not None), None)
    )
    if any(method is not None and method != auth_type for method in methods):
        raise CondaAuthError("Authentication type conflicts with the selected method")
    if auth_type != HTTP_BASIC_AUTH_NAME and any(
        login_options.get(key) is not None for key in ("username", "password")
    ):
        raise CondaAuthError("Options 'username' and 'password' can only be used with 'basic'")
    if auth_type != TOKEN_NAME and any(
        login_options.get(key) is not None for key in ("token_header", "token_template")
    ):
        raise CondaAuthError("Token header options can only be used with 'token'")
    return _login(
        channel,
        configuration=configuration,
        write_configuration=False,
        interactive=interactive,
        **login_options,
    )
