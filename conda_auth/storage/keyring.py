from __future__ import annotations

import json
from json import JSONDecodeError

import keyring
from keyring.errors import PasswordDeleteError

from ..constants import PLUGIN_NAME
from ..credentials import (
    CredentialRecord,
)
from ..exceptions import CondaAuthError
from .base import Storage

KEYRING_CREDENTIAL_SERVICE_PREFIX = f"{PLUGIN_NAME}::credential"
KEYRING_CREDENTIAL_USERNAME = "credential"


class KeyringStorage(Storage):
    """
    Storage implementation for keyring library
    """

    def set_credential(self, record: CredentialRecord) -> None:
        keyring.set_password(
            f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::{record.target}",
            KEYRING_CREDENTIAL_USERNAME,
            json.dumps(record.to_dict()),
        )

    def get_credential(self, target: str) -> CredentialRecord | None:
        payload = keyring.get_password(
            f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::{target}",
            KEYRING_CREDENTIAL_USERNAME,
        )
        if payload is None:
            return None

        try:
            data = json.loads(payload)
        except (JSONDecodeError, TypeError) as exc:
            raise CondaAuthError(f"Unable to read stored credential for {target!r}: {exc}")

        if not isinstance(data, dict):
            raise CondaAuthError(f"Stored credential for {target!r} is invalid")

        return CredentialRecord.from_dict(data)

    def delete_credential(self, target: str) -> None:
        try:
            keyring.delete_password(
                f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::{target}",
                KEYRING_CREDENTIAL_USERNAME,
            )
        except PasswordDeleteError:
            pass

    def legacy_service_name(self, auth_type: str, target: str) -> str:
        """
        Return the keyring service name used before structured records.
        """
        return f"{PLUGIN_NAME}::{auth_type}::{target}"

    def get_legacy_password(self, auth_type: str, target: str, username: str) -> str | None:
        """
        Return an old password-shaped keyring credential, if present.
        """
        return keyring.get_password(self.legacy_service_name(auth_type, target), username)

    def delete_legacy_password(self, auth_type: str, target: str, username: str) -> None:
        """
        Best-effort deletion for an old password-shaped keyring credential.
        """
        service_name = self.legacy_service_name(auth_type, target)
        try:
            if keyring.get_password(service_name, username) is None:
                return
            keyring.delete_password(service_name, username)
        except PasswordDeleteError:
            pass
