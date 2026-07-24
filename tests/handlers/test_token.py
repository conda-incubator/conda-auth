from __future__ import annotations

from types import SimpleNamespace

import pytest
from conda.exceptions import CondaError
from conda.models.channel import Channel
from keyring.errors import PasswordDeleteError

from conda_auth.constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.handlers.token import (
    TOKEN_FILE_ROOTS_ENV_VAR,
    TOKEN_NAME,
    TOKEN_PARAM_NAME,
    USERNAME,
    TokenAuthHandler,
    TokenAuthManager,
    manager,
)
from conda_auth.storage.keyring import KeyringStorage


def store_token_credential(channel: str, token: str) -> None:
    KeyringStorage().set_credential(
        CredentialRecord(
            target=channel,
            auth_type=TOKEN_NAME,
            username=USERNAME,
            token=token,
        )
    )


def store_custom_token_credential(
    channel: str,
    token: str,
    *,
    token_header: str,
    token_template: str,
) -> None:
    KeyringStorage().set_credential(
        CredentialRecord(
            target=channel,
            auth_type=TOKEN_NAME,
            username=USERNAME,
            token=token,
            token_header=token_header,
            token_template=token_template,
        )
    )


def write_mounted_token_file(tmp_path, monkeypatch, content: str = "token\n"):
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    monkeypatch.setenv(TOKEN_FILE_ROOTS_ENV_VAR, str(secret_root))
    token_file = secret_root / "conda_auth_secret"
    token_file.write_text(content)
    return token_file


@pytest.fixture(autouse=True)
def clean_up_manager_cache():
    """Makes sure the manager cache gets emptied after each test run"""
    context = manager._context
    yield
    manager._context = context
    manager.cache_clear()


@pytest.mark.parametrize(
    "settings",
    ({}, {TOKEN_PARAM_NAME: 1}),
    ids=("missing", "non-string"),
)
def test_token_auth_manager_rejects_missing_or_invalid_token(keyring, settings):
    """Missing and invalid tokens raise an auth error."""
    channel = Channel("tester")

    # No token exists in settings or keyring, so store() must fail.
    keyring(None)

    with pytest.raises(CondaAuthError, match="Token not found"):
        manager.store(channel, settings)


@pytest.mark.parametrize(
    ("channel_name", "settings"),
    (
        ("tester", {TOKEN_PARAM_NAME: "token"}),
        (
            "http://repo.example.com/private",
            {
                TOKEN_PARAM_NAME: "token",
                AUTH_ALLOW_PLAINTEXT_HTTP_PARAM: True,
            },
        ),
    ),
    ids=("secure", "explicit-plaintext-http"),
)
def test_token_auth_manager_with_token(keyring, channel_name, settings):
    """Valid tokens are cached for supported transports."""
    token = settings[TOKEN_PARAM_NAME]
    channel = Channel(channel_name)

    # CLI-supplied tokens should be accepted even when keyring starts empty.
    keyring(None)

    manager.store(channel, settings)

    assert manager._cache == {channel.canonical_name: (USERNAME, token)}


def test_token_legacy_operations_require_keyring(monkeypatch):
    monkeypatch.setattr(
        "conda_auth.handlers.token.storage",
        SimpleNamespace(backend=object()),
    )
    token_manager = TokenAuthManager()
    channel = Channel("tester")

    assert token_manager.migrate_legacy_credential_record(channel, None, "tester") is None
    token_manager.delete_legacy_credential_record(channel, None, "tester")


def test_token_legacy_migration_uses_auth_target(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[("conda-auth::token::shared", USERNAME)] = "secret"

    record = TokenAuthManager().migrate_legacy_credential_record(
        Channel("tester"),
        None,
        "shared",
    )

    assert record == CredentialRecord(
        target="shared",
        auth_type=TOKEN_NAME,
        username=USERNAME,
        token="secret",
        token_header="Authorization",
        token_template="Bearer {token}",
    )


def test_token_auth_manager_store_token_file_does_not_persist_secret(
    tmp_path, monkeypatch, keyring
):
    """The generic manager.store path keeps token-file auth out of keyring."""
    token_file = write_mounted_token_file(tmp_path, monkeypatch)
    settings = {"token_file": str(token_file)}
    channel = Channel("tester")
    keyring_mock, _ = keyring(None)

    manager.store(channel, settings)

    assert manager._cache == {channel.canonical_name: (USERNAME, "token")}
    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_manager_remove_existing_secret(keyring):
    """
    Test to make sure that removing a password that exist works.
    """
    secret = "secret"
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    # Token secrets always use the fixed token username.
    keyring_mock, _ = keyring(secret)

    manager.remove_secret(channel, settings)

    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


def test_basic_auth_manager_remove_non_existing_secret(keyring):
    """
    Test make sure that when removing a secret that does not exist, the appropriate
    exception and message is raised and shown.
    """
    secret = "secret"
    settings = {
        "username": USERNAME,
    }
    channel = Channel("tester")

    # Simulate keyring reporting that the stored token is already missing.
    keyring_mock, _ = keyring(secret)
    message = "Secret not found."
    keyring_mock.delete_password_side_effect = PasswordDeleteError(message)

    manager.remove_secret(channel, settings)

    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


@pytest.mark.parametrize(
    ("channel_name", "expected_header"),
    (
        ("channel", "Bearer token"),
        ("http://localhost", "Bearer token"),
    ),
    ids=("default-channel", "bearer"),
)
def test_token_auth_handler_sets_authorization_header(
    monkeypatch,
    keyring,
    context_factory,
    request_factory,
    channel_name,
    expected_header,
):
    token = "token"
    channel = Channel(channel_name)

    # Handler construction reads matching token settings from conda context.
    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)
    store_token_credential(channel.canonical_name, token)
    keyring_mock.get_password_calls.clear()
    keyring_mock.set_password_calls.clear()

    auth_handler = TokenAuthHandler(channel_name)

    # requests passes a mutable headers mapping through the auth handler.
    request = request_factory()

    request = auth_handler(request)

    assert request.headers == {"Authorization": expected_header}
    assert keyring_mock.get_password_calls == [
        (f"conda-auth::credential::{channel.canonical_name}", "credential")
    ]
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_sets_custom_token_header(
    monkeypatch, keyring, context_factory, request_factory
):
    """Stored token metadata controls the header name and value template."""
    channel_name = "channel"
    token = "token"
    channel = Channel(channel_name)

    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring(None)
    store_custom_token_credential(
        channel.canonical_name,
        token,
        token_header="X-Auth",
        token_template="Token {token}",
    )

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"X-Auth": "Token token"}


def test_token_auth_handler_reads_token_file_without_keyring(
    tmp_path, monkeypatch, keyring, context_factory, request_factory
):
    """File-backed token auth reads the mounted secret without touching keyring."""
    channel_name = "channel"
    token_file = write_mounted_token_file(tmp_path, monkeypatch)
    channel = Channel(channel_name)

    context = context_factory(
        [
            {
                "channel": channel.canonical_name,
                "auth": TOKEN_NAME,
                "token_file": str(token_file),
            }
        ]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"Authorization": "Bearer token"}
    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


@pytest.mark.parametrize(
    ("content", "message"),
    (
        ("", "must not be empty"),
        ("first\nsecond\n", "line breaks"),
        ("token\u0000", "control characters"),
    ),
    ids=("empty", "multi-line", "control-character"),
)
def test_token_auth_handler_rejects_invalid_token_file_content(
    tmp_path, monkeypatch, keyring, context_factory, content, message
):
    """File-backed token auth rejects empty or multi-line secret files."""
    channel_name = "channel"
    token_file = write_mounted_token_file(tmp_path, monkeypatch, content)

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "token_file": str(token_file)}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    with pytest.raises(CondaAuthError, match=message):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_rejects_relative_token_file(monkeypatch, keyring, context_factory):
    """Token file paths must be absolute to avoid cwd-dependent secret resolution."""
    channel_name = "channel"

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "token_file": "conda_auth_secret"}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    with pytest.raises(CondaAuthError, match="path must be absolute"):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_rejects_token_file_outside_secret_root(
    tmp_path, monkeypatch, keyring, context_factory
):
    """Token-file auth is restricted to mounted secret roots."""
    channel_name = "channel"
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    monkeypatch.setenv(TOKEN_FILE_ROOTS_ENV_VAR, str(secret_root))
    token_file = tmp_path / "conda_auth_secret"
    token_file.write_text("token\n")

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "token_file": str(token_file)}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    with pytest.raises(CondaAuthError, match="secret mount root"):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_rejects_oversized_token_file(
    tmp_path, monkeypatch, keyring, context_factory
):
    """Token files are bounded to avoid reading arbitrary large files as headers."""
    channel_name = "channel"
    token_file = write_mounted_token_file(tmp_path, monkeypatch, "x" * (64 * 1024 + 1))

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "token_file": str(token_file)}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    with pytest.raises(CondaAuthError, match="too large"):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_reports_missing_token_file(monkeypatch, keyring, context_factory):
    """Missing file-backed token secrets produce an actionable auth error."""
    channel_name = "channel"
    token_file = "/run/secrets/does_not_exist"

    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "token_file": token_file}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)

    with pytest.raises(CondaAuthError, match="Unable to read token file"):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_does_not_overwrite_custom_token_header(
    monkeypatch, keyring, context_factory, request_factory
):
    """Existing custom token headers are preserved."""
    channel_name = "channel"
    channel = Channel(channel_name)

    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring(None)
    store_custom_token_credential(
        channel.canonical_name,
        "token",
        token_header="X-Auth",
        token_template="Token {token}",
    )

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory(headers={"X-Auth": "existing"}))

    assert request.headers == {"X-Auth": "existing"}


def test_token_auth_handler_cache_reuses_keyring_secret(monkeypatch, keyring, context_factory):
    """Request-time auth loading only reads keyring once per channel."""
    channel_name = "http://localhost"
    token = "token"
    channel = Channel(channel_name)

    # Both handler constructions resolve the same token channel setting.
    context = context_factory([{"channel": channel.canonical_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)
    store_token_credential(channel.canonical_name, token)
    keyring_mock.get_password_calls.clear()
    keyring_mock.set_password_calls.clear()

    # The first construction primes the cache. The second should reuse it.
    TokenAuthHandler(channel_name)
    TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == [
        (f"conda-auth::credential::{channel.canonical_name}", "credential")
    ]
    assert keyring_mock.set_password_calls == []


@pytest.mark.parametrize(
    ("channel_name", "message"),
    (
        ("http://example.com/private-channel", "insecure HTTP channel"),
        ("ftp://example.com/private-channel", "unsupported channel scheme"),
        ("s3://bucket/private-channel", "unsupported channel scheme"),
        ("file:///tmp/private-channel", "unsupported channel scheme"),
    ),
    ids=("remote-http", "ftp", "s3", "file"),
)
def test_token_auth_handler_rejects_unsupported_transports_before_keyring(
    monkeypatch, keyring, context_factory, channel_name, message
):
    """Unsupported transports never receive token credentials."""

    # Transport validation happens before reading the configured keyring token.
    context = context_factory([{"channel": channel_name, "auth": TOKEN_NAME}])
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring("token")

    with pytest.raises(CondaAuthError, match=message):
        TokenAuthHandler(channel_name)

    assert keyring_mock.get_password_calls == []
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_allows_plaintext_http_when_configured(
    monkeypatch, keyring, context_factory, request_factory
):
    """Explicitly configured plaintext HTTP channels can receive token credentials."""
    channel_name = "http://example.com/private-channel"
    token = "token"

    # The opt-in is read from channel_settings at request-auth time.
    context = context_factory(
        [{"channel": channel_name, "auth": TOKEN_NAME, "auth_allow_plaintext_http": "True"}]
    )
    monkeypatch.setattr(manager, "_context", context)
    keyring_mock, _ = keyring(None)
    store_token_credential(channel_name, token)
    keyring_mock.get_password_calls.clear()
    keyring_mock.set_password_calls.clear()

    auth_handler = TokenAuthHandler(channel_name)
    request = auth_handler(request_factory())

    assert request.headers == {"Authorization": f"Bearer {token}"}
    assert keyring_mock.get_password_calls == [
        ("conda-auth::credential::http://example.com/private-channel", "credential")
    ]
    assert keyring_mock.set_password_calls == []


def test_token_auth_handler_no_token_available_error():
    """
    Test to make sure that we raise an error when no token can be found in the application's
    cache
    """
    channel_name = "http://localhost"

    with pytest.raises(
        CondaError,
        match=f"Unable to find authorization token for requests with channel {channel_name}",
    ):
        TokenAuthHandler(channel_name)


def test_token_auth_manager_get_auth_class():
    """
    Simple test to make sure we get the expected type back from the ``get_auth_class``
    method
    """
    assert manager.get_auth_class() is TokenAuthHandler


def test_token_auth_manager_get_auth_type():
    """
    Simple test to make sure we get the expected value back from the ``get_auth_type``
    method
    """
    assert manager.get_auth_type() == TOKEN_NAME


def test_token_auth_manager_get_secret_loads_from_channel_settings(keyring, context_factory):
    """get_secret loads credentials from matching channel settings."""
    channel = "channel"
    token = "token"

    # The manager resolves token settings from the injected conda context.
    context = context_factory(
        [{"channel": channel, "auth": TOKEN_NAME}],
        channels=(channel,),
    )
    keyring(None)
    store_token_credential(channel, token)

    token_manager = TokenAuthManager(context)

    assert token_manager.get_secret(channel) == (USERNAME, token)
    assert token_manager._cache == {channel: (USERNAME, token)}


def test_token_auth_manager_migrates_legacy_keyring_entry(keyring, context_factory):
    """Old token keyring entries are rewritten as structured records on first use."""
    channel = "channel"
    token = "legacy-token"

    context = context_factory(
        [{"channel": channel, "auth": TOKEN_NAME}],
        channels=(channel,),
    )
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[(f"conda-auth::{TOKEN_NAME}::{channel}", USERNAME)] = token

    token_manager = TokenAuthManager(context)

    assert token_manager.get_secret(channel) == (USERNAME, token)
    assert KeyringStorage().get_credential(channel) == CredentialRecord(
        target=channel,
        auth_type=TOKEN_NAME,
        username=USERNAME,
        token=token,
        token_header="Authorization",
        token_template="Bearer {token}",
    )
    assert (f"conda-auth::{TOKEN_NAME}::{channel}", USERNAME) not in keyring_mock.secrets


def test_token_auth_manager_removes_legacy_keyring_entry(keyring):
    """Logout cleanup also removes old token keyring entries."""
    channel = Channel("tester")
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[(f"conda-auth::{TOKEN_NAME}::{channel.canonical_name}", USERNAME)] = (
        "legacy-token"
    )

    manager.remove_secret(channel, {})

    assert (
        f"conda-auth::{TOKEN_NAME}::{channel.canonical_name}",
        USERNAME,
    ) not in keyring_mock.secrets


@pytest.mark.parametrize(
    ("settings", "message"),
    (
        ({"token": "token", "token_header": "Bad Header"}, "valid HTTP header field name"),
        ({"token": "token", "token_template": "Token"}, "must include"),
        ({"token": "token", "token_template": "Token {{token}}"}, "must include"),
        ({"token": "token", "token_template": "Token {missing}"}, "must include"),
        (
            {"token": "token", "token_template": "Token {token} {missing}"},
            "must only use",
        ),
        ({"token": "token", "token_template": "Token {token}\nX: y"}, "line breaks"),
        ({"token": "line\nbreak"}, "line breaks"),
        ({"token": "token\u0000"}, "control characters"),
    ),
    ids=(
        "bad-header",
        "missing-token",
        "escaped-token",
        "unknown-field",
        "extra-field",
        "line-break",
        "token-line-break",
        "token-control-character",
    ),
)
def test_token_auth_manager_rejects_invalid_header_config(keyring, settings, message):
    """Invalid token header configuration is rejected before persistence."""
    keyring(None)

    with pytest.raises(CondaAuthError, match=message):
        manager.store(Channel("tester"), settings)
