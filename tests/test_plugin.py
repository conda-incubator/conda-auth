from conda.cli.conda_argparse import BUILTIN_COMMANDS

from conda_auth import plugin
from conda_auth.constants import PLUGIN_NAME
from conda_auth.handlers import (
    HTTP_BASIC_AUTH_NAME,
    TOKEN_NAME,
    BasicAuthHandler,
    TokenAuthHandler,
)


def test_conda_subcommands_hook():
    """
    Test to make sure that this hook yields the correct objects.
    """
    objs = list(plugin.conda_subcommands())

    assert objs[0].name == "auth"
    assert objs[0].summary == "Authentication commands for conda"


def test_conda_pre_commands_hook():
    """
    Test to make sure that this hook yields the correct objects.
    """
    objs = list(plugin.conda_pre_commands())

    run_for = BUILTIN_COMMANDS.union(plugin.ENV_COMMANDS, plugin.BUILD_COMMANDS)

    assert objs[0].name == f"{PLUGIN_NAME}-{HTTP_BASIC_AUTH_NAME}"
    assert objs[0].run_for == run_for

    assert objs[1].name == f"{PLUGIN_NAME}-{TOKEN_NAME}"
    assert objs[1].run_for == run_for


def test_conda_auth_handlers_hook():
    """
    Test to make sure that this hook yields the correct objects.
    """
    objs = list(plugin.conda_auth_handlers())

    assert objs[0].name == HTTP_BASIC_AUTH_NAME
    assert objs[0].handler == BasicAuthHandler

    assert objs[1].name == TOKEN_NAME
    assert objs[1].handler == TokenAuthHandler
