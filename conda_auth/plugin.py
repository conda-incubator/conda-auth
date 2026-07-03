"""
A place to register plugin hooks
"""

from conda.cli.conda_argparse import BUILTIN_COMMANDS
from conda.plugins import hookimpl
from conda.plugins.types import CondaAuthHandler, CondaPreCommand, CondaSubcommand

from .cli import auth, configure_parser
from .constants import PLUGIN_NAME
from .handlers import (
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
    BasicAuthHandler,
    TokenAuthHandler,
    basic_auth_manager,
    token_auth_manager,
)

ENV_COMMANDS = {
    "env_config",
    "env_create",
    "env_export",
    "env_list",
    "env_remove",
    "env_update",
}

BUILD_COMMANDS = {
    "build",
    "convert",
    "debug",
    "develop",
    "index",
    "inspect",
    "metapackage",
    "render",
    "skeleton",
}


@hookimpl
def conda_subcommands():
    """
    Registers subcommands
    """
    yield CondaSubcommand(
        name="auth",
        action=auth,
        configure_parser=configure_parser,
        summary="Authentication commands for conda",
    )


@hookimpl
def conda_pre_commands():
    """
    Registers pre-command hooks
    """
    yield CondaPreCommand(
        name=f"{PLUGIN_NAME}-{HTTP_BASIC_AUTH_NAME}",
        action=basic_auth_manager.hook_action,
        run_for=BUILTIN_COMMANDS.union(ENV_COMMANDS, BUILD_COMMANDS),
    )
    yield CondaPreCommand(
        name=f"{PLUGIN_NAME}-{TOKEN_NAME}",
        action=token_auth_manager.hook_action,
        run_for=BUILTIN_COMMANDS.union(ENV_COMMANDS, BUILD_COMMANDS),
    )


@hookimpl
def conda_auth_handlers():
    """
    Registers auth handlers
    """
    yield CondaAuthHandler(name=HTTP_BASIC_AUTH_NAME, handler=BasicAuthHandler)
    yield CondaAuthHandler(name=TOKEN_NAME, handler=TokenAuthHandler)
