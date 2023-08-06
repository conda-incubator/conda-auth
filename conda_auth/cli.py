import click
from conda.models.channel import Channel


@click.command("login")
@click.argument("channel")
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
@click.argument("channel")
def logout(channel):
    """
    Logout of a channel
    """
    channel = Channel(channel)
    print(channel)


def logout_wrapper(args):
    """Logout of a channel"""
    logout(args=args, prog_name="conda logout", standalone_mode=False)
