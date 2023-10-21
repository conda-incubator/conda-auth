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
from .options import CustomOption

# Constants
AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
}

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

SUCCESSFUL_COLOR = "green"

FAILURE_COLOR = "red"

VALID_AUTH_CHOICES = tuple(AUTH_MANAGER_MAPPING.keys())

OPTION_DEFAULT = "CONDA_AUTH_DEFAULT"


def parse_channel(ctx, param, value):
    """
    Converts the channel name into a Channel object
    """
    return Channel(value)


class ExtraContext:
    """
    Used to provide more information about the running environment
    """

    def __init__(self):
        self.used_options = set()


def get_auth_manager(options, extra_context: ExtraContext) -> tuple[str, AuthManager]:
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
        return auth_type, auth_manager

    # we use http basic auth when "username" or "password" are present
    if "basic" in extra_context.used_options:
        auth_manager = basic_auth_manager
        auth_type = HTTP_BASIC_AUTH_NAME

    # we use token auth when "token" is present
    elif "token" in extra_context.used_options:
        auth_manager = token_auth_manager
        auth_type = TOKEN_NAME

    # raise error if authentication type not found
    else:
        raise CondaAuthError(
            click.style(
                "Please specify an authentication type to use"
                " with either the `--basic` or `--token` options.",
                fg=FAILURE_COLOR,
            )
        )

    return auth_type, auth_manager


def get_channel_settings(channel: str) -> MutableMapping[str, str] | None:
    """
    Retrieve the channel settings from the context object
    """
    for settings in context.channel_settings:
        if settings.get("channel") == channel:
            return dict(**settings)


@click.group("auth")
@click.pass_context
def group(ctx):
    """
    Commands for handling authentication within conda
    """
    ctx.obj = ExtraContext()


def auth_wrapper(args):
    """Authentication commands for conda"""
    group(args=args, prog_name="conda auth", standalone_mode=True)


@group.command("login")
@click.argument("channel", callback=parse_channel)
@click.option(
    "-u",
    "--username",
    help="Username to use for private channels using HTTP Basic Authentication",
    cls=CustomOption,
    prompt=True,
    mutually_exclusive=("token",),
    prompt_when="basic",
)
@click.option(
    "-p",
    "--password",
    help="Password to use for private channels using HTTP Basic Authentication",
    cls=CustomOption,
    prompt=True,
    hide_input=True,
    mutually_exclusive=("token",),
    prompt_when="basic",
)
@click.option(
    "-t",
    "--token",
    help="Token to use for private channels using an API token",
    prompt=True,
    prompt_required=False,
    cls=CustomOption,
    mutually_exclusive=("username", "password"),
)
@click.option(
    "-b",
    "--basic",
    is_flag=True,
    cls=CustomOption,
    help="Save login credentials as HTTP basic authentication",
)
@click.pass_obj
def login(extra_context: ExtraContext, channel: Channel, **kwargs):
    """
    Log in to a channel by storing the credentials or tokens associated with it
    """
    settings = {key: val for key, val in kwargs.items() if val is not None}

    auth_type, auth_manager = get_auth_manager(settings, extra_context)
    username: str | None = auth_manager.store(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGIN_MESSAGE, fg=SUCCESSFUL_COLOR))

    try:
        condarc = CondaRC()
        if auth_type == TOKEN_NAME:
            username = None
        condarc.update_channel_settings(channel.canonical_name, auth_type, username)
        condarc.save()
    except CondaRCError as exc:
        raise CondaAuthError(str(exc))


@group.command("logout")
@click.argument("channel", callback=parse_channel)
@click.pass_obj
def logout(extra_context: ExtraContext, channel: Channel):
    """
    Log out of a channel by removing any credentials or tokens associated with it.
    """
    settings = get_channel_settings(channel.canonical_name)

    if settings is None:
        raise CondaAuthError("Unable to find information about logged in session.")

    auth_type, auth_manager = get_auth_manager(settings, extra_context)
    auth_manager.remove_secret(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGOUT_MESSAGE, fg=SUCCESSFUL_COLOR))
