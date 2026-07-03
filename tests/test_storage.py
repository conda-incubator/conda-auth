import os
import subprocess
import sys

import pytest
from keyring.errors import NoKeyringError, PasswordDeleteError

from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.storage import get_storage_backend
from conda_auth.storage.keyring import (
    KEYRING_CREDENTIAL_SERVICE_PREFIX,
    KEYRING_CREDENTIAL_USERNAME,
    KeyringStorage,
)


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
    Structured credentials are stored as one keyring item per target.
    """
    keyring_mock, _ = keyring(None)
    backend = KeyringStorage()
    record = CredentialRecord(
        target="tester",
        auth_type="token",
        username="token",
        token="secret-token",
    )

    backend.set_credential(record)

    assert backend.get_credential("tester") == record
    assert keyring_mock.secrets[
        (
            f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::tester",
            KEYRING_CREDENTIAL_USERNAME,
        )
    ]


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
    keyring_mock.secrets[
        (
            f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::tester",
            KEYRING_CREDENTIAL_USERNAME,
        )
    ] = payload

    with pytest.raises(CondaAuthError, match=message):
        KeyringStorage().get_credential("tester")


def test_keyring_storage_deletes_structured_record(keyring):
    """
    Deleting a structured credential removes only that target record.
    """
    keyring(None)
    backend = KeyringStorage()
    backend.set_credential(CredentialRecord(target="tester", auth_type="token", token="secret"))

    backend.delete_credential("tester")

    assert backend.get_credential("tester") is None


def test_keyring_storage_ignores_structured_delete_error(keyring):
    keyring_mock, _ = keyring(None)
    keyring_mock.delete_password_side_effect = PasswordDeleteError()

    KeyringStorage().delete_credential("tester")

    assert keyring_mock.delete_password_calls == [
        (f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::tester", KEYRING_CREDENTIAL_USERNAME)
    ]


def test_keyring_storage_reads_legacy_password(keyring):
    """
    Old password-shaped entries can be read for one-time migration.
    """
    keyring_mock, _ = keyring(None)
    backend = KeyringStorage()
    keyring_mock.secrets[("conda-auth::token::tester", "token")] = "secret"

    assert backend.get_legacy_password("token", "tester", "token") == "secret"


def test_keyring_storage_deletes_legacy_password_when_present(keyring):
    """
    Legacy cleanup is best-effort and scoped to the old service name.
    """
    keyring_mock, _ = keyring(None)
    backend = KeyringStorage()
    keyring_mock.secrets[("conda-auth::token::tester", "token")] = "secret"

    backend.delete_legacy_password("token", "tester", "token")

    assert ("conda-auth::token::tester", "token") not in keyring_mock.secrets


def test_keyring_storage_ignores_legacy_delete_error(keyring):
    keyring_mock, _ = keyring("secret")
    keyring_mock.delete_password_side_effect = PasswordDeleteError()

    KeyringStorage().delete_legacy_password("token", "tester", "token")

    assert keyring_mock.delete_password_calls == [("conda-auth::token::tester", "token")]


def test_keyring_storage_delete_preserves_other_records(keyring):
    """
    Deleting one structured record does not require or mutate an index.
    """
    keyring(None)
    backend = KeyringStorage()
    backend.set_credential(CredentialRecord(target="one", auth_type="token", token="one"))
    backend.set_credential(CredentialRecord(target="two", auth_type="token", token="two"))

    backend.delete_credential("one")

    assert backend.get_credential("one") is None
    assert backend.get_credential("two") == CredentialRecord(
        target="two",
        auth_type="token",
        token="two",
    )
