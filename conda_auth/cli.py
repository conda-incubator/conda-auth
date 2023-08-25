from typing import NamedTuple

import click
from conda.base.context import context
from conda.models.channel import Channel

from .constants import OAUTH2_NAME, HTTP_BASIC_AUTH_NAME
from .exceptions import CondaAuthError
from .handlers import AuthManager, oauth2, basic_auth

AUTH_MANAGER_MAPPING = {
    OAUTH2_NAME: oauth2,
    HTTP_BASIC_AUTH_NAME: basic_auth,
}


class ChannelData(NamedTuple):
    """Used for providing commands with all the channel information they need"""

    channel: Channel
    settings: dict[str, str]
    manager: AuthManager


def get_example(channel):
    """Function used to print a nice example for our users 😀"""
    return (
        "Example:\n\n"
        "channel_settings:\n"
        f"  - channel: {channel}\n"
        "    auth: conda-auth-basic-auth\n"
        "    username: user_one"
    )


def validate_channel(ctx, param, value):
    """
    Makes sure the channel exists in conda's configuration and returns a ``ChannelData`` object
    if so.

    TODO: This function is doing a lot more than a simple "validation"; Should be refactored or
          renamed.
    """
    context.__init__()

    provided_channel = Channel(value)

    for settings in context.channel_settings:
        if channel_name := settings.get("channel"):
            auth_type = settings.get("auth")
            auth_manager = AUTH_MANAGER_MAPPING.get(auth_type)

            if auth_manager is None:
                available_auth_types = ", ".join(AUTH_MANAGER_MAPPING.keys())
                raise CondaAuthError(
                    f'Invalid configured authentication handler for "{channel_name}". '
                    'Please make sure "auth" is defined in "channel_settings". '
                    f"Possible choices: {available_auth_types}\n\n"
                    f"{get_example(channel_name)}"
                )

            channel = Channel(channel_name)

            if provided_channel == channel:
                return ChannelData(
                    channel=channel, settings=settings, manager=auth_manager
                )

    raise CondaAuthError(
        f"Unrecognized channel: {value}. Make sure this channel is defined in your "
        'conda configuration and has an entry in "channel_settings".\n\n'
        f"{get_example(value)}"
    )


@click.command("login")
@click.argument("channel", callback=validate_channel)
def login(channel: ChannelData):
    """
    Login to a channel
    """
    channel.manager.authenticate(channel.channel, channel.settings)


def login_wrapper(args):
    """Login to a channel"""
    login(args=args, prog_name="conda login", standalone_mode=True)


@click.command("logout")
@click.argument("channel", callback=validate_channel)
def logout(channel):
    """
    Logout of a channel
    """
    channel.manager.remove_secrets(channel.channel, **channel.settings)


def logout_wrapper(args):
    """Logout of a channel"""
    logout(args=args, prog_name="conda logout", standalone_mode=True)
