"""
A place to register plugin hooks
"""

from conda.plugins import hookimpl
from conda.plugins.types import CondaAuthHandler, CondaSubcommand


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
