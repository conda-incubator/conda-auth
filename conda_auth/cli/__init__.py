from __future__ import annotations

import argparse
import sys
import time
from fnmatch import fnmatch
from getpass import getpass
from typing import Literal, Any

from conda.base.context import context
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import json, yaml
from conda.common.url import urlparse as conda_urlparse
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..exceptions import CondaAuthError
from ..handlers import (
    HTTP_BASIC_AUTH_NAME,
    OAUTH2_NAME,
    TOKEN_NAME,
    AuthManager,
    basic_auth_manager,
    oauth2_auth_manager,
    token_auth_manager,
)
from ..handlers.base import allows_plaintext_http, validate_secure_channel
from ..oauth2_client import perform_oauth_login, with_target
from ..storage import storage
from .config import (
    get_updated_channel_settings,
    remove_channel_settings,
    update_channel_settings,
)
from .oauth2 import build_oauth_login_config
from .parser import PROMPT_VALUE, build_parser, configure_parser
from .status import output_status
from .status import status as get_status

AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
    OAUTH2_NAME: oauth2_auth_manager,
}

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

__all__ = (
    "SUCCESSFUL_LOGIN_MESSAGE",
    "SUCCESSFUL_LOGOUT_MESSAGE",
    "auth",
    "build_parser",
    "configure_parser",
    "get_updated_channel_settings",
    "login",
    "logout",
    "remove_channel_settings",
    "update_channel_settings",
)


def prompt_text(prompt: str) -> str:
    """
    Prompt for visible text input.
    """
    return input(prompt)


def prompt_secret(prompt: str) -> str:
    """
    Prompt for secret input.
    """
    return getpass(prompt)


def _find_channel_settings(channel: Channel) -> dict[str, Any] | None:
    """
    Return the first channel_settings entry from the active conda context that
    matches *channel*, or ``None`` if no entry is found.

    Matching is done via canonical-name equality.
    """
    for settings in context.channel_settings:
        settings: dict[str, Any]
        configured = settings.get("channel")

        if isinstance(configured, str) and Channel(configured).canonical_name == channel.canonical_name:
            return dict(settings)

    return None


def _channel_settings_exist_outside_user_condarc(
    channel: Channel, user_condarc_content: dict
) -> bool:
    """
    Return True if a ``channel_settings`` entry with auth configuration for
    *channel* already exists in the active conda context **from a source other
    than the user condarc**.
    """
    # Check: does the merged context have an auth entry for this channel?
    context_entry = _find_channel_settings(channel)
    if not context_entry or not context_entry.get("auth"):
        return False

    # Check: does the user condarc already have an entry for this channel?
    user_settings = user_condarc_content.get("channel_settings", []) or []
    if not isinstance(user_settings, list):
        return False

    for entry in user_settings:
        if isinstance(entry, dict) and isinstance(entry.get("channel"), str):
            if Channel(entry["channel"]).canonical_name == channel.canonical_name:
                return False  # user condarc already has an entry — let normal update proceed

    # Auth config exists in the merged context but NOT in the user condarc.
    return True


def output_success(args: argparse.Namespace, message: str) -> None:
    """
    Output a successful command result.
    """
    if getattr(args, "json", False) is True:
        print(json.dumps({"success": True, "message": message}))
    else:
        print(message)


def get_auth_manager(
    auth: str | None = None,
    basic: bool | None = None,
    token: str | Literal[False] | None = None,
    oauth2: bool | None = None,
    **kwargs,
) -> tuple[str, AuthManager]:
    """
    Based on CLI options provided, return the correct auth manager to use.
    """
    if auth:  # set in .condarc
        pass
    elif basic:  # defined on CLI
        auth = HTTP_BASIC_AUTH_NAME
    elif token is not None:  # defined on CLI
        auth = TOKEN_NAME
    elif oauth2:  # defined on CLI
        auth = OAUTH2_NAME
    else:
        raise CondaAuthError("Missing authentication type.")

    # check if auth defined maps to a valid auth manager
    if not (auth_manager := AUTH_MANAGER_MAPPING.get(auth)):
        raise CondaAuthError(
            f"Invalid authentication type. Valid types are: {set(AUTH_MANAGER_MAPPING)}"
        )

    return auth, auth_manager


def login(channel: Channel, **kwargs):
    """
    Log in to a channel by storing the credentials or tokens associated with it.
    """
    # Guard: reject login if already-valid credentials exist in the keyring.
    existing = storage.get_credential(channel.canonical_name)
    if existing is not None:
        is_valid = True
        if existing.expires_at is not None:
            is_valid = existing.expires_at > int(time.time())
        if is_valid:
            raise CondaAuthError(
                f"Already logged in to '{channel.canonical_name}'. "
                "Run 'conda auth logout <channel>' first to log in again."
            )

    auth_type, auth_manager = get_auth_manager(**kwargs)
    allow_plaintext_http = allows_plaintext_http(kwargs)
    channel_setting = channel.canonical_name
    credential_target = channel_setting
    validate_secure_channel(channel, allow_plaintext_http=allow_plaintext_http)

    record = None
    username: str | None = None
    secret: str | None = None
    if auth_type == OAUTH2_NAME:
        ch_settings = _find_channel_settings(channel)
        oauth_config = build_oauth_login_config(channel, kwargs, channel_settings=ch_settings)
        record = with_target(perform_oauth_login(oauth_config), channel)
    else:
        extra_params = {
            param: kwargs.get(param)
            for param in auth_manager.get_config_parameters()
            if kwargs.get(param) is not None
        }
        extra_params["auth_target"] = credential_target
        if allow_plaintext_http:
            extra_params[AUTH_ALLOW_PLAINTEXT_HTTP_PARAM] = True
        username, secret = auth_manager.fetch_secret(channel, extra_params, use_cache=False)

    # Track whether the user's condarc file was updated
    wrote_user_condarc = False

    try:
        with ConfigurationFile.from_user_condarc() as config:
            if not _channel_settings_exist_outside_user_condarc(channel, config.content):
                update_channel_settings(
                    config,
                    channel_setting,
                    auth_type,
                    None,
                    auth_target=credential_target,
                    allow_plaintext_http=allow_plaintext_http,
                )
                wrote_user_condarc = True
    except (CondaError, OSError, yaml.YAMLError) as exc:
        auth_manager.cache_clear(channel.canonical_name)
        raise CondaAuthError(str(exc))

    try:
        if record is not None:
            storage.set_credential(record)
        elif username is not None and secret is not None:
            auth_manager.save_credentials(
                channel,
                username,
                secret,
                allow_plaintext_http=allow_plaintext_http,
                target=credential_target,
                settings=extra_params,
            )
    except Exception as credential_error:
        auth_manager.cache_clear(channel.canonical_name)
        if wrote_user_condarc:
            try:
                with ConfigurationFile.from_user_condarc() as config:
                    remove_channel_settings(config, channel_setting)
            except (CondaError, OSError, yaml.YAMLError) as rollback_error:
                raise CondaAuthError(
                    f"{credential_error}. Failed to roll back channel settings: {rollback_error}"
                ) from credential_error
        raise


def logout(channel: Channel):
    """
    Log out of a channel by removing any credentials or tokens associated with it.
    """
    settings = _find_channel_settings(channel)
    if not settings:
        raise CondaAuthError("Unable to find information about logged in session.")

    auth_type, auth_manager = get_auth_manager(**settings)

    try:
        with ConfigurationFile.from_user_condarc() as config:
            removed_auth_settings = remove_channel_settings(config, channel.canonical_name)
            if not removed_auth_settings:
                credential = storage.get_credential(channel.canonical_name)
                if credential is None:
                    raise CondaAuthError(
                        "Unable to remove authentication settings from the user condarc. "
                        "Remove them from the configuration source where they are defined."
                    )
    except (CondaError, OSError, yaml.YAMLError) as exc:
        raise CondaAuthError(str(exc))

    auth_manager.remove_secret(channel, settings)
    auth_manager.cache_clear(channel.canonical_name)


def auth(args: argparse.Namespace) -> None:
    """
    Commands for handling authentication within conda.
    """
    if args.command is None:
        args.parser.print_help()
        return

    if args.command == "login":
        token = args.token

        # Build the channel early so we can look up channel_settings for
        # auto-detection before the auth-type check below.
        channel = Channel(args.channel)

        if not args.basic and token is None and not args.oauth2:
            # No explicit auth-type flag — try to infer from channel_settings.
            inferred = _find_channel_settings(channel)
            inferred_auth = inferred.get("auth") if inferred else None
            if inferred_auth == OAUTH2_NAME:
                args.oauth2 = True
            elif inferred_auth == HTTP_BASIC_AUTH_NAME:
                args.basic = True
            elif inferred_auth == TOKEN_NAME:
                token = PROMPT_VALUE
            else:
                raise CondaAuthError("Missing option 'basic' / 'token' / 'oauth2'.")

        if token is not None or args.oauth2:
            if args.username is not None:
                raise CondaAuthError("Option 'username' cannot be used with 'token' or 'oauth2'")
            if args.password is not None:
                raise CondaAuthError("Option 'password' cannot be used with 'token' or 'oauth2'")

        validate_secure_channel(
            channel,
            allow_plaintext_http=args.allow_plaintext_http,
        )

        if token is PROMPT_VALUE:
            token = prompt_secret("Token: ")

        oauth_client_secret = args.oauth_client_secret
        if oauth_client_secret is PROMPT_VALUE:
            oauth_client_secret = prompt_secret("OAuth client secret: ")
        oauth_output_stream = sys.stderr if args.json else None

        if args.basic:
            username = args.username
            password = args.password

            if username is None:
                username = prompt_text("Username: ")
            if password is None:
                password = prompt_secret("Password: ")

            login(
                channel,
                basic=True,
                username=username,
                password=password,
                auth_allow_plaintext_http=args.allow_plaintext_http,
            )
            output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
            return

        login(
            channel,
            token=token,
            oauth2=args.oauth2,
            oauth_issuer_url=args.oauth_issuer_url,
            oauth_client_id=args.oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            oauth_flow=args.oauth_flow,
            oauth_scopes=args.oauth_scopes,
            oauth_redirect_uri=args.oauth_redirect_uri,
            user_agent=args.user_agent,
            oauth_output_stream=oauth_output_stream,
            auth_allow_plaintext_http=args.allow_plaintext_http,
        )
        output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
    elif args.command == "logout":
        logout(Channel(args.channel))
        output_success(args, SUCCESSFUL_LOGOUT_MESSAGE)
    elif args.command == "status":
        output_status(args, get_status(args.channel))
