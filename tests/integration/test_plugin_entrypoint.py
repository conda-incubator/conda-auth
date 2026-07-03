from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "args",
    (
        ("info", "--json"),
        ("auth", "--help"),
    ),
    ids=("info", "auth-help"),
)
def test_conda_entrypoint_does_not_require_storage_backend(conda_runner, args):
    conda_runner.env["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"

    result = conda_runner.run(*args)

    assert result.returncode == 0, result.stderr or result.stdout
    assert "Error while loading conda entry point: conda-auth" not in result.stderr
    if args[0] == "info":
        assert json.loads(result.stdout)["conda_version"]
