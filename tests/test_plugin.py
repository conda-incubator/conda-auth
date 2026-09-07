from __future__ import annotations

import subprocess
import sys

import pytest

from conda_auth import plugin
from conda_auth.cli import configure_parser
from conda_auth.constants import PROXY_NETWORK_COMMANDS
from conda_auth.handlers import (
    HTTP_BASIC_AUTH_NAME,
    OAUTH2_NAME,
    TOKEN_NAME,
    BasicAuthHandler,
    OAuth2AuthHandler,
    TokenAuthHandler,
)


def test_conda_subcommands_hook():
    """
    Test to make sure that this hook yields the correct objects.
    """
    objs = list(plugin.conda_subcommands())

    assert objs[0].name == "auth"
    assert objs[0].summary == "Authentication commands for conda"
    assert objs[0].configure_parser is configure_parser


@pytest.mark.parametrize(
    ("index", "name", "handler"),
    (
        (0, HTTP_BASIC_AUTH_NAME, BasicAuthHandler),
        (1, TOKEN_NAME, TokenAuthHandler),
        (2, OAUTH2_NAME, OAuth2AuthHandler),
    ),
    ids=("basic-auth", "token", "oauth2"),
)
def test_conda_auth_handlers_hook(index, name, handler):
    """The auth handler hook registers supported auth schemes."""
    # Hook order is part of the registration surface conda sees.
    objs = list(plugin.conda_auth_handlers())

    assert objs[index].name == name
    assert objs[index].handler == handler


def test_conda_pre_commands_hook(monkeypatch):
    """The proxy pre-command hook runs only for network commands."""
    applied_credentials = []

    class FakeProxyAuthManager:
        def apply_to_context(self):
            applied_credentials.append(True)

    monkeypatch.setattr("conda_auth.proxy.ProxyAuthManager", FakeProxyAuthManager)

    objs = list(plugin.conda_pre_commands())

    assert len(objs) == 1
    assert objs[0].name == "conda-auth-proxy"
    assert objs[0].run_for == set(PROXY_NETWORK_COMMANDS)
    objs[0].action("search")
    assert applied_credentials == [True]


def test_plugin_import_does_not_eagerly_import_runtime_modules():
    """Importing plugin hooks does not load CLI, storage, or keyring."""
    code = """
import sys
import conda_auth.plugin

eager_modules = {
    "conda_auth.cli",
    "conda_auth.storage",
    "keyring",
}
loaded_modules = sorted(eager_modules.intersection(sys.modules))
if loaded_modules:
    raise SystemExit(f"eager runtime imports: {loaded_modules}")
"""

    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
