from __future__ import annotations

import subprocess
import sys

from conda_auth import plugin
from conda_auth.cli import configure_parser
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
    assert objs[0].configure_parser is configure_parser


def test_conda_auth_handlers_hook():
    """
    Test to make sure that this hook yields the correct objects.
    """
    objs = list(plugin.conda_auth_handlers())

    assert objs[0].name == HTTP_BASIC_AUTH_NAME
    assert objs[0].handler == BasicAuthHandler

    assert objs[1].name == TOKEN_NAME
    assert objs[1].handler == TokenAuthHandler


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
