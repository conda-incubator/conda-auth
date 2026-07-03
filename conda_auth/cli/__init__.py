from __future__ import annotations

import argparse
import sys
from contextlib import suppress
from getpass import getpass
from typing import Literal

from conda.base.context import context
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import json, yaml
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import (
    AUTH_ALLOW_PLAINTEXT_HTTP_PARAM,
    PROXY_COMMAND_NAME,
    SUCCESSFUL_LOGIN_MESSAGE,
    SUCCESSFUL_LOGOUT_MESSAGE,
)
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
from ..oauth2_client import perform_oauth_login, revoke_oauth_record, with_target
from ..storage import storage
from ..verification import verify_channel_credentials
from .config import (
    get_updated_channel_settings,
    remove_channel_settings,
    update_channel_settings,
)
from .oauth2 import build_oauth_login_config
from .parser import PROMPT_VALUE, build_parser, configure_parser
from .proxy import auth_proxy_command
from .status import output_status
from .status import status as get_status

AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
    OAUTH2_NAME: oauth2_auth_manager,
}

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
    auth_type, auth_manager = get_auth_manager(**kwargs)
    allow_plaintext_http = allows_plaintext_http(kwargs)
    verify = bool(kwargs.get("verify"))
    channel_setting = channel.canonical_name
    credential_target = channel_setting
    validate_secure_channel(channel, allow_plaintext_http=allow_plaintext_http)

    record = None
    username: str | None = None
    secret: str | None = None
    if auth_type == OAUTH2_NAME:
        oauth_config = build_oauth_login_config(channel, kwargs)
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

    try:
        with ConfigurationFile.from_user_condarc() as config:
            update_channel_settings(
                config,
                channel_setting,
                auth_type,
                None,
                auth_target=credential_target,
                allow_plaintext_http=allow_plaintext_http,
            )
    except (CondaError, OSError, yaml.YAMLError) as exc:
        auth_manager.cache_clear(channel.canonical_name)
        raise CondaAuthError(str(exc))

    stored_record = None
    try:
        if record is not None:
            storage.set_credential(record)
            stored_record = record
        elif username is not None and secret is not None:
            stored_record = auth_manager.save_credentials(
                channel,
                username,
                secret,
                allow_plaintext_http=allow_plaintext_http,
                target=credential_target,
                settings=extra_params,
            )
        if verify and stored_record is not None:
            verify_channel_credentials(channel, stored_record)
    except Exception as credential_error:
        auth_manager.cache_clear(channel.canonical_name)
        rollback_error = None
        try:
            with ConfigurationFile.from_user_condarc() as config:
                remove_channel_settings(config, channel_setting)
        except (CondaError, OSError, yaml.YAMLError) as exc:
            rollback_error = exc
        if stored_record is not None:
            if stored_record.auth_type == OAUTH2_NAME:
                with suppress(Exception):
                    revoke_oauth_record(stored_record)
            with suppress(Exception):
                storage.delete_credential(stored_record.target)
        if rollback_error is not None:
            raise CondaAuthError(
                f"{credential_error}. Failed to roll back channel settings: {rollback_error}"
            ) from credential_error
        raise


def logout(channel: Channel):
    """
    Log out of a channel by removing any credentials or tokens associated with it.
    """
    settings = next(
        (
            settings
            for settings in context.channel_settings
            if settings.get("channel") == channel.canonical_name
        ),
        None,
    )
    if not settings:
        raise CondaAuthError("Unable to find information about logged in session.")

    auth_type, auth_manager = get_auth_manager(**settings)

    try:
        with ConfigurationFile.from_user_condarc() as config:
            removed_auth_settings = remove_channel_settings(config, channel.canonical_name)
            if not removed_auth_settings:
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

        if not args.basic and token is None and not args.oauth2:
            raise CondaAuthError("Missing option 'basic' / 'token' / 'oauth2'.")

        if token is not None or args.oauth2:
            if args.username is not None:
                raise CondaAuthError("Option 'username' cannot be used with 'token' or 'oauth2'")
            if args.password is not None:
                raise CondaAuthError("Option 'password' cannot be used with 'token' or 'oauth2'")

        if token is None and (args.token_header is not None or args.token_template is not None):
            raise CondaAuthError("Token header options can only be used with 'token'")

        channel = Channel(args.channel)
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
                verify=args.verify,
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
            token_header=args.token_header,
            token_template=args.token_template,
            verify=args.verify,
            auth_allow_plaintext_http=args.allow_plaintext_http,
        )
        output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
        return

    if args.command == "logout":
        logout(Channel(args.channel))
        output_success(args, SUCCESSFUL_LOGOUT_MESSAGE)
        return

    if args.command == "status":
        output_status(args, get_status(args.channel))
        return

    if args.command == PROXY_COMMAND_NAME:
        auth_proxy_command(args)
        return

    raise CondaAuthError(f"Unknown command: {args.command}")
