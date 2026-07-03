"""
A place to register plugin hooks
"""

from conda.plugins import hookimpl
from conda.plugins.types import CondaAuthHandler, CondaPreCommand, CondaSubcommand


@hookimpl
def conda_subcommands():
    """
    Registers subcommands
    """
    from .cli import auth, configure_parser

    yield CondaSubcommand(
        name="auth",
        action=auth,
        configure_parser=configure_parser,
        summary="Authentication commands for conda",
    )


@hookimpl
def conda_auth_handlers():
    """
    Registers auth handlers
    """
    from .handlers import (
        HTTP_BASIC_AUTH_NAME,
        OAUTH2_NAME,
        TOKEN_NAME,
        BasicAuthHandler,
        OAuth2AuthHandler,
        TokenAuthHandler,
    )

    yield CondaAuthHandler(name=HTTP_BASIC_AUTH_NAME, handler=BasicAuthHandler)
    yield CondaAuthHandler(name=TOKEN_NAME, handler=TokenAuthHandler)
    yield CondaAuthHandler(name=OAUTH2_NAME, handler=OAuth2AuthHandler)


@hookimpl
def conda_pre_commands():
    """
    Apply configured proxy credentials before network commands run.
    """
    from .constants import PROXY_NETWORK_COMMANDS
    from .proxy import ProxyAuthManager

    proxy_manager = ProxyAuthManager()

    def apply_proxy_credentials(_command: str) -> None:
        proxy_manager.apply_to_context()

    yield CondaPreCommand(
        name="conda-auth-proxy",
        action=apply_proxy_credentials,
        run_for=set(PROXY_NETWORK_COMMANDS),
    )
