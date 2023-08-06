import click
from conda.base.context import context
from conda.models.channel import Channel

from .exceptions import CondaAuthError


def validate_channel(ctx, param, value):
    """Makes sure the channel exists in conda's configuration"""
    context.__init__()

    for settings in context.channel_settings:
        if channel_name := settings.get("channel"):
            channel_name = channel_name.lower()
            if channel_name == value.lower():
                return channel_name

    raise CondaAuthError(
        f"Unrecognized channel: {value}. Make sure this channel is defined in your "
        "conda configuration and has an entry in `channel_settings`."
    )


@click.command("login")
@click.argument("channel", callback=validate_channel)
def login(channel):
    """
    Login to a channel
    """
    channel = Channel(channel)
    print(channel)


def login_wrapper(args):
    """Login to a channel"""
    login(args=args, prog_name="conda login", standalone_mode=False)


@click.command("logout")
@click.argument("channel", callback=validate_channel)
def logout(channel):
    """
    Logout of a channel
    """
    channel = Channel(channel)
    print(channel)


def logout_wrapper(args):
    """Logout of a channel"""
    logout(args=args, prog_name="conda logout", standalone_mode=False)
