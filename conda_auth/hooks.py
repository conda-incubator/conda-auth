"""
A place to register plugin hooks
"""
from conda.plugins import CondaAuthHandler, CondaPreCommand, CondaSubcommand, hookimpl

from .handlers import OAuth2Handler, BasicAuthHandler
from .handlers.oauth2 import manager as oauth2_manager
from .handlers.basic_auth import manager as basic_auth_manager
from .constants import OAUTH2_NAME, HTTP_BASIC_AUTH_NAME
from .cli import auth_wrapper


@hookimpl
def conda_subcommands():
    """
    Registers subcommands
    """
    yield CondaSubcommand(
        name="auth", action=auth_wrapper, summary="Authentication commands for conda"
    )


@hookimpl
def conda_pre_commands():
    """
    Registers pre-command hooks
    """
    yield CondaPreCommand(
        name=f"{HTTP_BASIC_AUTH_NAME}-collect_credentials",
        action=basic_auth_manager.hook_action,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )
    yield CondaPreCommand(
        name=f"{OAUTH2_NAME}-collect_token",
        action=oauth2_manager.hook_action,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )


@hookimpl
def conda_auth_handlers():
    """
    Registers auth handlers
    """
    yield CondaAuthHandler(name=HTTP_BASIC_AUTH_NAME, handler=BasicAuthHandler)
    yield CondaAuthHandler(name=OAUTH2_NAME, handler=OAuth2Handler)
