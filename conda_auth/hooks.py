"""
A place to register plugin hooks
"""
from conda.plugins import CondaAuth, CondaPreCommand, hookimpl

from . import basic_auth
from .constants import PLUGIN_NAME


@hookimpl
def conda_pre_commands():
    yield CondaPreCommand(
        name=f"{PLUGIN_NAME}_collect_credentials",
        action=basic_auth.collect_credentials,
        run_for={"search", "install", "update", "notices", "create", "search"},
    )


@hookimpl
def conda_auth():
    """
    Register our session class
    """
    yield CondaAuth(name=PLUGIN_NAME, auth_class=basic_auth.CondaHTTPBasicAuth)
