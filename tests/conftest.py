import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO

import pytest


@dataclass
class CliResult:
    exit_code: int
    output: str
    stdout: str
    stderr: str
    exc_info: tuple | None


class ArgparseRunner:
    """
    Small CLI runner for argparse commands.
    """

    def invoke(self, command, args=None, input=None):
        from conda_auth.cli import build_parser

        stdout = StringIO()
        stderr = StringIO()
        old_stdin = sys.stdin
        parser = build_parser()

        if input is not None:
            sys.stdin = StringIO(input)

        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    namespace = parser.parse_args(args or [])
                    command(namespace)
                except SystemExit as exc:
                    exc_info = sys.exc_info()
                    exit_code = exc.code
                    if not isinstance(exit_code, int):
                        exit_code = 1
                except BaseException:
                    exc_info = sys.exc_info()
                    exit_code = 1
                else:
                    exc_info = None
                    exit_code = 0
        finally:
            sys.stdin = old_stdin

        stdout_value = stdout.getvalue()
        stderr_value = stderr.getvalue()

        return CliResult(
            exit_code=exit_code,
            output=f"{stdout_value}{stderr_value}",
            stdout=stdout_value,
            stderr=stderr_value,
            exc_info=exc_info,
        )


@pytest.fixture
def keyring(mocker):
    """
    Used to mock keyring for the duration of our tests
    """

    def _keyring(secret):
        get_keyring = mocker.patch("conda_auth.storage.get_keyring")
        keyring_storage = mocker.patch("conda_auth.storage.keyring.keyring")
        keyring_storage.get_password.return_value = secret

        return keyring_storage, get_keyring

    return _keyring


@pytest.fixture
def runner():
    """
    CLI test runner used for all tests
    """
    yield ArgparseRunner()


@pytest.fixture
def condarc(mocker):
    """
    Mocks the user condarc configuration file object.
    """
    config = mocker.MagicMock()
    config.__enter__.return_value = config
    config.__exit__.return_value = None
    config.content = {}
    mocker.patch("conda_auth.cli.ConfigurationFile.from_user_condarc", return_value=config)

    return config
