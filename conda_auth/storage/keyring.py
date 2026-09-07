from __future__ import annotations

import json
import sys
import warnings
from json import JSONDecodeError

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from ..constants import PLUGIN_NAME
from ..credentials import (
    CredentialRecord,
)
from ..exceptions import CondaAuthError
from .base import Storage

KEYRING_CREDENTIAL_SERVICE_PREFIX = f"{PLUGIN_NAME}::credential"
KEYRING_CREDENTIAL_USERNAME = "credential"
MACOS_KEYCHAIN_ACCESS_HINT = (
    "macOS Keychain can deny access after the Python interpreter changes, for example "
    "after a conda update or when using conda-auth from another environment. Re-run "
    "the command from this environment and approve the Keychain prompt, or remove the "
    "stale conda-auth item in Keychain Access and log in again."
)


class KeyringStorage(Storage):
    """
    Storage implementation for keyring library
    """

    def keyring_error_message(self, action: str, target: str, exc: KeyringError) -> str:
        """
        Return an actionable storage error message for a keyring failure.
        """
        message = f"Unable to {action} credential for {target!r}: {exc}"
        if self.is_macos_keychain_error(exc):
            message = f"{message}. {MACOS_KEYCHAIN_ACCESS_HINT}"
        return message

    def is_macos_keychain_error(self, exc: KeyringError) -> bool:
        """
        Return whether an error is likely caused by macOS Keychain access control.
        """
        if sys.platform != "darwin":
            return False

        message = str(exc).lower()
        return "keychain" in message or "(-25244" in message

    def is_missing_credential_error(self, exc: KeyringError) -> bool:
        """
        Return whether a delete error means the keyring item is already absent.
        """
        message = str(exc).lower()
        return any(
            marker in message
            for marker in (
                "not found",
                "does not exist",
                "no such",
                "(-25300",
            )
        )

    def set_credential(self, record: CredentialRecord) -> None:
        try:
            keyring.set_password(
                f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::{record.target}",
                KEYRING_CREDENTIAL_USERNAME,
                json.dumps(record.to_dict()),
            )
        except KeyringError as exc:
            raise CondaAuthError(self.keyring_error_message("store", record.target, exc)) from exc

    def get_credential(self, target: str) -> CredentialRecord | None:
        try:
            payload = keyring.get_password(
                f"{KEYRING_CREDENTIAL_SERVICE_PREFIX}::{target}",
                KEYRING_CREDENTIAL_USERNAME,
            )
        except KeyringError as exc:
            raise CondaAuthError(self.keyring_error_message("access stored", target, exc)) from exc
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
        except PasswordDeleteError as exc:
            if self.is_missing_credential_error(exc):
                return
            # macOS Keychain can deny deletion after the creating Python binary changes.
            # Treat deletion as best-effort so logout can leave a harmless orphaned
            # item instead of failing after removing the user-visible auth config.
            warnings.warn(
                self.keyring_error_message("delete", target, exc),
                RuntimeWarning,
                stacklevel=2,
            )

    def legacy_service_name(self, auth_type: str, target: str) -> str:
        """
        Return the keyring service name used by conda-auth before structured records.
        """
        return f"{PLUGIN_NAME}::{auth_type}::{target}"

    def get_legacy_password(self, auth_type: str, target: str, username: str) -> str | None:
        """
        Return an old password-shaped keyring credential, if present.
        """
        try:
            return keyring.get_password(
                self.legacy_service_name(auth_type, target),
                username,
            )
        except KeyringError as exc:
            raise CondaAuthError(
                self.keyring_error_message("access legacy stored", target, exc)
            ) from exc

    def delete_legacy_password(self, auth_type: str, target: str, username: str) -> None:
        """
        Best-effort deletion for an old password-shaped keyring credential.
        """
        service_name = self.legacy_service_name(auth_type, target)
        try:
            if keyring.get_password(service_name, username) is None:
                return
            keyring.delete_password(service_name, username)
        except KeyringError as exc:
            if self.is_missing_credential_error(exc):
                return
            warnings.warn(
                self.keyring_error_message("delete legacy", target, exc),
                RuntimeWarning,
                stacklevel=2,
            )
