"""
A place to register plugin hooks
"""
from conda.plugins import CondaAuthHandler, CondaPreCommand, CondaSubcommand, hookimpl

from .handlers import (
    oauth2_manager,
    basic_auth_manager,
    token_auth_manager,
    OAuth2Handler,
    BasicAuthHandler,
    TokenAuthHandler,
    OAUTH2_NAME,
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
)
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
    yield CondaPreCommand(
        name=f"{TOKEN_NAME}-collect_token",
        action=token_auth_manager.hook_action,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )


@hookimpl
def conda_auth_handlers():
    """
    Registers auth handlers
    """
    yield CondaAuthHandler(name=HTTP_BASIC_AUTH_NAME, handler=BasicAuthHandler)
    yield CondaAuthHandler(name=OAUTH2_NAME, handler=OAuth2Handler)
    yield CondaAuthHandler(name=TOKEN_NAME, handler=TokenAuthHandler)
