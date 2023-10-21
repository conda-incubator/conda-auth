from __future__ import annotations

from typing import Literal

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
from .options import ConditionalOption

# Constants
AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
}

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

SUCCESSFUL_COLOR = "green"

FAILURE_COLOR = "red"

OPTION_DEFAULT = "CONDA_AUTH_DEFAULT"


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
            "Invalid authentication type. "
            f"Valid types are: {set(AUTH_MANAGER_MAPPING)}"
        )

    return auth, auth_manager


@click.group("auth", context_settings={"help_option_names": ["-h", "--help"]})
def auth():
    """
    Commands for handling authentication within conda
    """


@auth.command("login")
@click.argument("channel", callback=lambda ctx, param, value: Channel(value))
@click.option(
    "-b",
    "--basic",
    help="Save login credentials as HTTP basic authentication",
    cls=ConditionalOption,
    is_flag=True,
    mutually_exclusive={"token"},
    not_required_if={"token"},
)
@click.option(
    "-u",
    "--username",
    help="Username to use for private channels using HTTP Basic Authentication",
    cls=ConditionalOption,
    prompt_when={"basic"},
    mutually_exclusive={"token"},
)
@click.option(
    "-p",
    "--password",
    help="Password to use for private channels using HTTP Basic Authentication",
    cls=ConditionalOption,
    prompt_when={"basic"},
    hide_input=True,
    mutually_exclusive={"token"},
)
@click.option(
    "-t",
    "--token",
    help="Token to use for private channels using an API token",
    cls=ConditionalOption,
    prompt=True,
    prompt_required=False,
    mutually_exclusive={"basic", "username", "password"},
    not_required_if={"basic"},
)
def login(channel: Channel, **kwargs):
    """
    Log in to a channel by storing the credentials or tokens associated with it
    """
    auth_type, auth_manager = get_auth_manager(**kwargs)
    username: str | None = auth_manager.store(channel, kwargs)

    click.echo(click.style(SUCCESSFUL_LOGIN_MESSAGE, fg=SUCCESSFUL_COLOR))

    try:
        condarc = CondaRC()
        if auth_type == TOKEN_NAME:
            username = None
        condarc.update_channel_settings(channel.canonical_name, auth_type, username)
        condarc.save()
    except CondaRCError as exc:
        raise CondaAuthError(str(exc))


@auth.command("logout")
@click.argument("channel", callback=lambda ctx, param, value: Channel(value))
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
    auth_manager.remove_secret(channel, settings)

    click.echo(click.style(SUCCESSFUL_LOGOUT_MESSAGE, fg=SUCCESSFUL_COLOR))
