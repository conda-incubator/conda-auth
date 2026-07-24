from __future__ import annotations

import argparse
from getpass import getpass
from typing import Literal

from conda.base.context import context
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import json, yaml
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..exceptions import CondaAuthError
from ..handlers import (
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
    AuthManager,
    basic_auth_manager,
    token_auth_manager,
)
from ..handlers.base import allows_plaintext_http, validate_secure_channel
from .config import (
    get_updated_channel_settings,
    remove_channel_settings,
    update_channel_settings,
)
from .parser import PROMPT_VALUE, build_parser, configure_parser
from .status import output_status
from .status import status as get_status

AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
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
    **kwargs,
) -> tuple[str, AuthManager]:
    """
    Based on CLI options provided, return the correct auth manager to use.
    """
    if auth:  # set in .condarc
        pass
    elif basic:  # defined on CLI
        auth = HTTP_BASIC_AUTH_NAME
    elif token:  # defined on CLI
        auth = TOKEN_NAME
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
    channel_setting = channel.canonical_name
    credential_target = channel_setting
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

    try:
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

        if not args.basic and token is None:
            raise CondaAuthError("Missing option 'basic' / 'token'.")

        if token is not None:
            if args.username is not None:
                raise CondaAuthError("Option 'username' cannot be used with 'token'")
            if args.password is not None:
                raise CondaAuthError("Option 'password' cannot be used with 'token'")

        channel = Channel(args.channel)
        validate_secure_channel(
            channel,
            allow_plaintext_http=args.allow_plaintext_http,
        )

        if token is not None:
            if token is PROMPT_VALUE:
                token = prompt_secret("Token: ")
            login(
                channel,
                token=token,
                auth_allow_plaintext_http=args.allow_plaintext_http,
            )
            output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
            return

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
    elif args.command == "logout":
        logout(Channel(args.channel))
        output_success(args, SUCCESSFUL_LOGOUT_MESSAGE)
    elif args.command == "status":
        output_status(args, get_status(args.channel))
