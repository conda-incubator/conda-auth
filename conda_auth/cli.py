from __future__ import annotations

from collections.abc import MutableMapping

import click
from conda.base.context import context
from conda.models.channel import Channel

from .condarc import CondaRC, CondaRCError
from .exceptions import CondaAuthError
from .handlers import (
    AuthManager,
    basic_auth_manager,
    token_auth_manager,
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
)

# Constants
AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
}

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

SUCCESSFUL_COLOR = "green"

VALID_AUTH_CHOICES = tuple(AUTH_MANAGER_MAPPING.keys())


def parse_channel(ctx, param, value):
    """
    Converts the channel name into a Channel object
    """
    return Channel(value)


def get_auth_manager(options) -> tuple[str, AuthManager]:
    """
    Based on CLI options provided, return the correct auth manager to use.
    """
    auth_type = options.get("auth")

    if auth_type is not None:
        auth_manager = AUTH_MANAGER_MAPPING.get(auth_type)
        if auth_manager is None:
            raise CondaAuthError(
                f'Invalid authentication type. Valid types are: "{", ".join(VALID_AUTH_CHOICES)}"'
            )

    # we use http basic auth when "username" or "password" are present
    elif options.get("username") is not None or options.get("password") is not None:
        auth_manager = basic_auth_manager
        auth_type = HTTP_BASIC_AUTH_NAME

    # we use token auth when "token" is present
    elif options.get("token") is not None:
        auth_manager = token_auth_manager
        auth_type = TOKEN_NAME

    # default authentication handler
    else:
        auth_manager = basic_auth_manager
        auth_type = HTTP_BASIC_AUTH_NAME

    return auth_type, auth_manager


def get_channel_settings(channel: str) -> MutableMapping[str, str] | None:
    """
    Retrieve the channel settings from the context object
    """
    for settings in context.channel_settings:
        if settings.get("channel") == channel:
            return dict(**settings)


@click.group("auth")
def group():
    """
    Commands for handling authentication within conda
    """


def auth_wrapper(args):
    """Authentication commands for conda"""
    group(args=args, prog_name="conda auth", standalone_mode=True)


@group.command("login")
@click.option(
    "-u",
    "--username",
    help="Username to use for private channels using HTTP Basic Authentication",
)
@click.option(
    "-p",
    "--password",
    help="Password to use for private channels using HTTP Basic Authentication",
)
@click.option(
    "-t",
    "--token",
    help="Token to use for private channels using an API token",
)
@click.option(
    "-a",
    "--auth",
    help="Specify the authentication type you would like to use",
    type=click.Choice(VALID_AUTH_CHOICES),
)
@click.argument("channel", callback=parse_channel)
def login(channel: Channel, **kwargs):
    """
    Log in to a channel by storing the credentials or tokens associated with it
    """
    kwargs = {key: val for key, val in kwargs.items() if val is not None}
    settings = get_channel_settings(channel.canonical_name) or {}
    settings.update(kwargs)

    auth_type, auth_manager = get_auth_manager(settings)

    username = auth_manager.store(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGIN_MESSAGE, fg=SUCCESSFUL_COLOR))

    try:
        condarc = CondaRC()
        condarc.update_channel_settings(channel.canonical_name, username, auth_type)
        condarc.save()
    except CondaRCError as exc:
        raise CondaAuthError(str(exc))


@group.command("logout")
@click.argument("channel", callback=parse_channel)
def logout(channel: Channel):
    """
    Log out of a by removing any credentials or tokens associated with it.
    """
    settings = get_channel_settings(channel.canonical_name)

    if settings is None:
        raise CondaAuthError("Unable to find information about logged in session.")

    settings["type"] = settings["auth"]
    auth_type, auth_manager = get_auth_manager(settings)
    auth_manager.remove_secret(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGOUT_MESSAGE, fg=SUCCESSFUL_COLOR))
