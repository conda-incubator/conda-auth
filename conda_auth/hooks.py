"""
A place to register plugin hooks
"""
from conda.plugins import CondaAuthHandler, CondaPreCommand, CondaSubcommand, hookimpl

from .handlers import (
    basic_auth_manager,
    token_auth_manager,
    BasicAuthHandler,
    TokenAuthHandler,
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
)
from .cli import auth_wrapper
from .constants import PLUGIN_NAME


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
        name=f"{PLUGIN_NAME}-{HTTP_BASIC_AUTH_NAME}",
        action=basic_auth_manager.hook_action,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )
    yield CondaPreCommand(
        name=f"{PLUGIN_NAME}-{TOKEN_NAME}",
        action=token_auth_manager.hook_action,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )


@hookimpl
def conda_auth_handlers():
    """
    Registers auth handlers
    """
    yield CondaAuthHandler(name=HTTP_BASIC_AUTH_NAME, handler=BasicAuthHandler)
    yield CondaAuthHandler(name=TOKEN_NAME, handler=TokenAuthHandler)
