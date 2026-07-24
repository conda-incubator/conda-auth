import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from io import StringIO
from typing import Any

import pytest


@dataclass
class FakeContext:
    channel_settings: list[dict[str, object]] = field(default_factory=list)
    channels: tuple[str, ...] = ()


@dataclass
class FakeCondarc:
    content: dict[str, Any] = field(default_factory=dict)
    exit_side_effect: BaseException | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.exit_side_effect is not None:
            raise self.exit_side_effect
        return None


@dataclass
class FakeRequest:
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RecordingKeyring:
    secret: str | None
    secrets: dict[tuple[str, str], str] = field(default_factory=dict)
    get_password_calls: list[tuple[str, str]] = field(default_factory=list)
    set_password_calls: list[tuple[str, str, str]] = field(default_factory=list)
    delete_password_calls: list[tuple[str, str]] = field(default_factory=list)
    get_password_side_effect: BaseException | None = None
    set_password_side_effect: BaseException | None = None
    delete_password_side_effect: BaseException | None = None

    def get_password(self, key_id: str, username: str) -> str | None:
        self.get_password_calls.append((key_id, username))
        if self.get_password_side_effect is not None:
            raise self.get_password_side_effect
        if key_id.startswith("conda-auth::credential::") or key_id == "conda-auth::index":
            return self.secrets.get((key_id, username))
        return self.secrets.get((key_id, username), self.secret)

    def set_password(self, key_id: str, username: str, password: str) -> None:
        self.set_password_calls.append((key_id, username, password))
        if self.set_password_side_effect is not None:
            raise self.set_password_side_effect
        self.secrets[(key_id, username)] = password

    def delete_password(self, key_id: str, username: str) -> None:
        self.delete_password_calls.append((key_id, username))
        if self.delete_password_side_effect is not None:
            raise self.delete_password_side_effect
        self.secrets.pop((key_id, username), None)


@dataclass
class RecordingGetKeyring:
    backend: RecordingKeyring
    side_effect: BaseException | type[BaseException] | None = None
    calls: list[tuple] = field(default_factory=list)

    def __call__(self):
        self.calls.append(())
        if self.side_effect is not None:
            raise self.side_effect
        return self.backend


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
        keyring_storage.secrets = {}
        keyring_storage.get_password_calls = []
        keyring_storage.set_password_calls = []
        keyring_storage.delete_password_calls = []
        keyring_storage.get_password_side_effect = None
        keyring_storage.set_password_side_effect = None
        keyring_storage.delete_password_side_effect = None

        def get_password(key_id, username):
            keyring_storage.get_password_calls.append((key_id, username))
            if keyring_storage.get_password_side_effect is not None:
                raise keyring_storage.get_password_side_effect
            if key_id.startswith("conda-auth::credential::") or key_id == "conda-auth::index":
                return keyring_storage.secrets.get((key_id, username))
            return keyring_storage.secrets.get((key_id, username), secret)

        def set_password(key_id, username, password):
            keyring_storage.set_password_calls.append((key_id, username, password))
            if keyring_storage.set_password_side_effect is not None:
                raise keyring_storage.set_password_side_effect
            keyring_storage.secrets[(key_id, username)] = password

        def delete_password(key_id, username):
            keyring_storage.delete_password_calls.append((key_id, username))
            if keyring_storage.delete_password_side_effect is not None:
                raise keyring_storage.delete_password_side_effect
            keyring_storage.secrets.pop((key_id, username), None)

        keyring_storage.get_password.side_effect = get_password
        keyring_storage.set_password.side_effect = set_password
        keyring_storage.delete_password.side_effect = delete_password

        return keyring_storage, get_keyring

    return _keyring


@pytest.fixture
def runner():
    """
    CLI test runner used for all tests
    """
    yield ArgparseRunner()


@pytest.fixture
def context_factory():
    def _context_factory(channel_settings=None, channels=()):
        return FakeContext(channel_settings=channel_settings or [], channels=channels)

    return _context_factory


@pytest.fixture
def request_factory():
    return FakeRequest


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
