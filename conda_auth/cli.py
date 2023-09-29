from __future__ import annotations

from collections.abc import MutableMapping

import click
from conda.base.context import context
from conda.models.channel import Channel

from .condarc import CondaRC, CondaRCError
from .constants import OAUTH2_NAME, HTTP_BASIC_AUTH_NAME
from .exceptions import CondaAuthError, InvalidCredentialsError
from .handlers import AuthManager, oauth2_manager, basic_auth_manager

AUTH_MANAGER_MAPPING = {
    OAUTH2_NAME: oauth2_manager,
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
}
SUCCESSFUL_LOGIN_MESSAGE = "Successfully logged in"
SUCCESSFUL_LOGOUT_MESSAGE = "Successfully logged out"
MAX_LOGIN_ATTEMPTS = 3


def parse_channel(ctx, param, value):
    """
    Converts the channel name into a Channel object
    """
    return Channel(value)


def get_auth_manager(options) -> tuple[str, AuthManager]:
    """
    Based on CLI options provided, return the correct auth manager to use.
    """
    auth_type = options.get("type") or options.get("auth")

    if auth_type is not None:
        auth_manager = AUTH_MANAGER_MAPPING.get(auth_type)
        if auth_manager is None:
            raise CondaAuthError(
                f'Invalid authentication type. Valid types are: "{HTTP_BASIC_AUTH_NAME}"'
            )

    # we use http basic auth when username or password are present
    elif options.get("username") is not None or options.get("password") is not None:
        auth_manager = basic_auth_manager
        auth_type = HTTP_BASIC_AUTH_NAME

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
@click.option("-u", "--username", help="Username to use for HTTP Basic Authentication")
@click.option("-p", "--password", help="Password to use for HTTP Basic Authentication")
@click.option(
    "-t",
    "--type",
    help='Manually specify the type of authentication to use. Choices are: "http-basic"',
)
@click.argument("channel", callback=parse_channel)
def login(channel: Channel, **kwargs):
    """
    Login to a channel
    """
    kwargs = {key: val for key, val in kwargs.items() if val is not None}
    settings = get_channel_settings(channel.canonical_name) or {}
    settings.update(kwargs)

    auth_type, auth_manager = get_auth_manager(settings)
    attempts = 0

    while True:
        try:
            username = auth_manager.authenticate(channel, settings)
            break
        except InvalidCredentialsError as exc:
            auth_manager.remove_channel_cache(channel.canonical_name)
            attempts += 1
            if attempts >= MAX_LOGIN_ATTEMPTS:
                raise CondaAuthError(f"Max attempts reached; {exc}")

    click.echo(click.style(SUCCESSFUL_LOGIN_MESSAGE, fg="green"))

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
    Logout of a channel
    """
    settings = get_channel_settings(channel.canonical_name)

    if settings is None:
        raise CondaAuthError("Unable to find information about logged in session.")

    settings["type"] = settings["auth"]
    auth_type, auth_manager = get_auth_manager(settings)
    auth_manager.remove_secret(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGOUT_MESSAGE, fg="green"))
