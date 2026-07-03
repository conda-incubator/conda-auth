from __future__ import annotations

import os
import subprocess
import sys

import pytest
from keyring.errors import KeyringError, NoKeyringError, PasswordDeleteError

from conda_auth.credentials import (
    CredentialRecord,
)
from conda_auth.exceptions import CondaAuthError
from conda_auth.storage import get_storage_backend
from conda_auth.storage.keyring import KeyringStorage


def test_no_available_storage_backend(keyring):
    """
    Test to make sure we've covered the lines where an exception is raise
    if no storage backend can be found.
    """
    _, get_keyring_mock = keyring(None)

    get_keyring_mock.side_effect = NoKeyringError()

    with pytest.raises(CondaAuthError, match="Unable to find a credential storage backend"):
        get_storage_backend()


def test_plugin_import_does_not_require_storage_backend():
    """
    Importing the conda plugin must not fail when credentials are not needed.
    """
    env = os.environ.copy()
    env["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"

    result = subprocess.run(
        [sys.executable, "-c", "import conda_auth.plugin"],
        capture_output=True,
        env=env,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_keyring_storage_stores_structured_record(keyring):
    """
    Structured credentials can be stored and loaded by target.
    """
    keyring(None)
    backend = KeyringStorage()
    record = CredentialRecord(
        target="tester",
        auth_type="token",
        username="token",
        token="secret-token",
        token_header="X-Auth",
        token_template="Token {token}",
    )

    backend.set_credential(record)

    assert backend.get_credential("tester") == record


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        ("{", "Unable to read stored credential"),
        ("[]", "Stored credential for 'tester' is invalid"),
    ),
    ids=("malformed-json", "non-object-json"),
)
def test_keyring_storage_rejects_invalid_records(keyring, payload, message):
    keyring_mock, _ = keyring(None)
    backend = KeyringStorage()
    backend.set_credential(CredentialRecord(target="tester", auth_type="token"))
    service, username, _ = keyring_mock.set_password_calls[-1]
    keyring_mock.secrets[(service, username)] = payload

    with pytest.raises(CondaAuthError, match=message):
        backend.get_credential("tester")


def test_keyring_storage_deletes_structured_record(keyring):
    """
    Deleting a structured credential removes the target record.
    """
    keyring(None)
    backend = KeyringStorage()
    backend.set_credential(CredentialRecord(target="tester", auth_type="token", token="secret"))

    backend.delete_credential("tester")

    assert backend.get_credential("tester") is None


def test_keyring_storage_reads_legacy_password(keyring):
    """Old password-shaped entries can be read by keyring service and username."""
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[("conda-auth::token::tester", "token")] = "legacy-token"
    backend = KeyringStorage()

    assert backend.get_legacy_password("token", "tester", "token") == "legacy-token"


def test_keyring_storage_deletes_legacy_password_when_present(keyring):
    """Old password-shaped entries are removed only when they exist."""
    keyring_mock, _ = keyring(None)
    keyring_mock.secrets[("conda-auth::token::tester", "token")] = "legacy-token"
    backend = KeyringStorage()

    backend.delete_legacy_password("token", "tester", "token")

    assert ("conda-auth::token::tester", "token") not in keyring_mock.secrets
    assert keyring_mock.get_password_calls == [("conda-auth::token::tester", "token")]
    assert keyring_mock.delete_password_calls == [("conda-auth::token::tester", "token")]


def test_keyring_storage_skips_missing_legacy_password_deletion(keyring):
    """Missing old password-shaped entries do not produce delete warnings."""
    keyring_mock, _ = keyring(None)
    backend = KeyringStorage()

    backend.delete_legacy_password("token", "tester", "token")

    assert keyring_mock.get_password_calls == [("conda-auth::token::tester", "token")]
    assert keyring_mock.delete_password_calls == []


@pytest.mark.parametrize(
    ("operation", "warning_match", "expected_call"),
    (
        (
            "structured",
            "Unable to delete credential for 'tester'",
            ("conda-auth::credential::tester", "credential"),
        ),
        (
            "legacy",
            "Unable to delete legacy credential for 'tester'",
            ("conda-auth::token::tester", "token"),
        ),
    ),
    ids=("structured", "legacy"),
)
def test_keyring_storage_warns_when_delete_is_denied(
    keyring, operation, warning_match, expected_call
):
    """Delete is best-effort and visible when the OS keychain refuses item removal."""
    keyring_mock, _ = keyring(None)
    if operation == "legacy":
        keyring_mock.secrets[("conda-auth::token::tester", "token")] = "legacy-token"
    keyring_mock.delete_password_side_effect = PasswordDeleteError(
        "Can't delete password in keychain: (-25244, 'Unknown Error')"
    )
    backend = KeyringStorage()

    with pytest.warns(RuntimeWarning, match=warning_match):
        if operation == "structured":
            backend.delete_credential("tester")
        else:
            backend.delete_legacy_password("token", "tester", "token")

    assert keyring_mock.delete_password_calls == [expected_call]


@pytest.mark.parametrize(
    "message",
    ("Secret not found.", "Item does not exist.", "No such credential.", "(-25300, missing)"),
    ids=("not-found", "does-not-exist", "no-such", "macos-missing"),
)
def test_keyring_storage_ignores_missing_delete_errors(keyring, message):
    """Deleting an already-missing keyring item is a no-op."""
    keyring_mock, _ = keyring(None)
    keyring_mock.delete_password_side_effect = PasswordDeleteError(message)
    backend = KeyringStorage()

    backend.delete_credential("tester")

    assert keyring_mock.delete_password_calls == [("conda-auth::credential::tester", "credential")]


def test_keyring_storage_delete_preserves_other_records(keyring):
    """Deleting one credential does not remove other target records."""
    keyring(None)
    backend = KeyringStorage()
    backend.set_credential(CredentialRecord(target="first", auth_type="token", token="first"))
    backend.set_credential(CredentialRecord(target="second", auth_type="token", token="second"))

    backend.delete_credential("first")

    assert backend.get_credential("first") is None
    assert backend.get_credential("second") == CredentialRecord(
        target="second",
        auth_type="token",
        token="second",
    )


def test_keyring_storage_wraps_get_errors(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.get_password_side_effect = KeyringError("Keychain access denied")
    backend = KeyringStorage()

    with pytest.raises(
        CondaAuthError,
        match="Unable to access stored credential for 'tester': Keychain access denied",
    ):
        backend.get_credential("tester")


@pytest.mark.parametrize(
    ("operation", "expected_message"),
    (
        ("get", "Unable to access stored credential for 'tester'"),
        ("set", "Unable to store credential for 'tester'"),
        ("delete", "Unable to delete credential for 'tester'"),
    ),
    ids=("get", "set", "delete"),
)
def test_keyring_storage_explains_macos_keychain_errors(
    monkeypatch, keyring, operation, expected_message
):
    keyring_mock, _ = keyring(None)
    keychain_error = "Can't access password in keychain: (-25244, 'Unknown Error')"
    if operation == "get":
        keyring_mock.get_password_side_effect = KeyringError(keychain_error)
    elif operation == "set":
        keyring_mock.set_password_side_effect = KeyringError(keychain_error)
    else:
        keyring_mock.delete_password_side_effect = PasswordDeleteError(keychain_error)
    monkeypatch.setattr("conda_auth.storage.keyring.sys.platform", "darwin")
    backend = KeyringStorage()

    if operation == "delete":
        with pytest.warns(RuntimeWarning) as warnings:
            backend.delete_credential("tester")
        message = str(warnings[0].message)
    else:
        with pytest.raises(CondaAuthError) as exc_info:
            if operation == "get":
                backend.get_credential("tester")
            else:
                backend.set_credential(
                    CredentialRecord(target="tester", auth_type="token", token="secret")
                )
        message = exc_info.value.message

    assert expected_message in message
    assert "Python interpreter changes" in message
    assert "Keychain Access" in message


def test_keyring_storage_wraps_set_errors(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.set_password_side_effect = KeyringError("Keychain access denied")
    backend = KeyringStorage()

    with pytest.raises(
        CondaAuthError,
        match="Unable to store credential for 'tester': Keychain access denied",
    ):
        backend.set_credential(
            CredentialRecord(target="tester", auth_type="token", token="secret")
        )
