"""
A place to register plugin hooks
"""
from conda.plugins import CondaAuthHandler, CondaPreCommand, hookimpl

from . import basic_auth, oauth2
from .constants import OAUTH2_NAME, HTTP_BASIC_AUTH_NAME


@hookimpl
def conda_pre_commands():
    yield CondaPreCommand(
        name=f"{HTTP_BASIC_AUTH_NAME}-collect_credentials",
        action=basic_auth.collect_credentials,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )
    yield CondaPreCommand(
        name=f"{OAUTH2_NAME}-collect_token",
        action=oauth2.collect_token,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )


@hookimpl
def conda_auth_handlers():
    """
    Register our auth handlers
    """
    yield CondaAuthHandler(
        name=HTTP_BASIC_AUTH_NAME,
        handler=basic_auth.CondaHTTPBasicAuth
    )
    yield CondaAuthHandler(
        name=OAUTH2_NAME,
        handler=oauth2.CondaOAuth2
    )
