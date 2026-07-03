from __future__ import annotations

import argparse
from collections.abc import Mapping
from getpass import getpass
from typing import Literal

from conda.base.context import context
from conda.cli.condarc import ConfigurationFile
from conda.cli.helpers import add_parser_json
from conda.common.serialize import json, yaml
from conda.exceptions import CondaError
from conda.models.channel import Channel

from .exceptions import CondaAuthError
from .handlers import (
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
    AuthManager,
    basic_auth_manager,
    token_auth_manager,
)

# Constants
AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
}

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

PROMPT_VALUE = object()

AUTH_CHANNEL_SETTING_KEYS = frozenset(
    (
        "auth",
        "username",
        "password",
        "token",
    )
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


def get_updated_channel_settings(
    channel_settings: list,
    channel: str,
    auth_type: str,
    username: str | None = None,
) -> list:
    """
    Replace the auth-owned settings for a single channel.
    """
    updated_settings: dict[str, object] = {"channel": channel}
    last_channel_index = next(
        (
            index
            for index, settings in reversed(list(enumerate(channel_settings)))
            if isinstance(settings, Mapping) and settings.get("channel") == channel
        ),
        None,
    )
    if last_channel_index is not None:
        updated_settings.update(
            {
                key: value
                for key, value in channel_settings[last_channel_index].items()
                if key not in AUTH_CHANNEL_SETTING_KEYS
            }
        )

    updated_settings["auth"] = auth_type
    if username is not None:
        updated_settings["username"] = username

    if last_channel_index is None:
        return [*channel_settings, updated_settings]

    return [
        updated_settings if index == last_channel_index else settings
        for index, settings in enumerate(channel_settings)
    ]


def update_channel_settings(
    config: ConfigurationFile,
    channel: str,
    auth_type: str,
    username: str | None = None,
) -> None:
    """
    Update the user's channel auth settings via conda's configuration file API.
    """
    channel_settings = config.content.get("channel_settings", []) or []
    if not isinstance(channel_settings, list):
        raise CondaAuthError("Expected 'channel_settings' to be a list")

    config.content["channel_settings"] = get_updated_channel_settings(
        channel_settings,
        channel,
        auth_type,
        username,
    )


def remove_channel_settings(config: ConfigurationFile, channel: str) -> bool:
    """
    Remove the user's channel auth settings via conda's configuration file API.
    """
    channel_settings = config.content.get("channel_settings", []) or []
    if not isinstance(channel_settings, list):
        raise CondaAuthError("Expected 'channel_settings' to be a list")

    removed_auth_settings = False
    updated_channel_settings = []
    for settings in channel_settings:
        if not isinstance(settings, Mapping) or settings.get("channel") != channel:
            updated_channel_settings.append(settings)
            continue

        removed_auth_settings = removed_auth_settings or any(
            key in settings for key in AUTH_CHANNEL_SETTING_KEYS
        )
        updated_settings = {
            key: value for key, value in settings.items() if key not in AUTH_CHANNEL_SETTING_KEYS
        }
        if updated_settings != {"channel": channel}:
            updated_channel_settings.append(updated_settings)

    config.content["channel_settings"] = updated_channel_settings
    return removed_auth_settings


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
    Log in to a channel by storing the credentials or tokens associated with it
    """
    auth_type, auth_manager = get_auth_manager(**kwargs)
    extra_params = {param: kwargs.get(param) for param in auth_manager.get_config_parameters()}
    username, secret = auth_manager.fetch_secret(channel, extra_params, use_cache=False)

    try:
        config_username: str | None = username
        if auth_type == TOKEN_NAME:
            config_username = None
        with ConfigurationFile.from_user_condarc() as config:
            update_channel_settings(config, channel.canonical_name, auth_type, config_username)
    except (CondaError, OSError, yaml.YAMLError) as exc:
        auth_manager.cache_clear(channel.canonical_name)
        raise CondaAuthError(str(exc))

    try:
        auth_manager.save_credentials(channel, username, secret)
    except Exception as credential_error:
        auth_manager.cache_clear(channel.canonical_name)
        try:
            with ConfigurationFile.from_user_condarc() as config:
                remove_channel_settings(config, channel.canonical_name)
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


def configure_parser(parser: argparse.ArgumentParser) -> None:
    """
    Configure the conda auth subcommand parser.
    """
    parser.set_defaults(parser=parser)
    subparsers = parser.add_subparsers(dest="command")

    login_parser = subparsers.add_parser(
        "login",
        help="Log in to a channel",
        description="Log in to a channel by storing the credentials or tokens associated with it",
    )
    login_parser.add_argument("channel")
    auth_options = login_parser.add_mutually_exclusive_group()
    auth_options.add_argument(
        "-b",
        "--basic",
        action="store_true",
        help="Save login credentials as HTTP basic authentication",
    )
    auth_options.add_argument(
        "-t",
        "--token",
        nargs="?",
        const=PROMPT_VALUE,
        metavar="TOKEN",
        help="Token to use for private channels using an API token",
    )
    login_parser.add_argument(
        "-u",
        "--username",
        help="Username to use for private channels using HTTP Basic Authentication",
    )
    login_parser.add_argument(
        "-p",
        "--password",
        help="Password to use for private channels using HTTP Basic Authentication",
    )
    add_parser_json(login_parser)
    login_parser.set_defaults(parser=login_parser)

    logout_parser = subparsers.add_parser(
        "logout",
        help="Log out of a channel",
        description="Log out of a channel by removing any credentials or tokens associated with it",
    )
    logout_parser.add_argument("channel")
    add_parser_json(logout_parser)


def build_parser(prog_name: str = "conda auth") -> argparse.ArgumentParser:
    """
    Build a standalone parser for tests and direct invocation.
    """
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description="Commands for handling authentication within conda",
    )
    configure_parser(parser)
    return parser


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
            if token is PROMPT_VALUE:
                token = prompt_secret("Token: ")
            login(Channel(args.channel), token=token)
            output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
            return

        username = args.username
        password = args.password

        if username is None:
            username = prompt_text("Username: ")
        if password is None:
            password = prompt_secret("Password: ")

        login(Channel(args.channel), basic=True, username=username, password=password)
        output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
    elif args.command == "logout":
        logout(Channel(args.channel))
        output_success(args, SUCCESSFUL_LOGOUT_MESSAGE)
