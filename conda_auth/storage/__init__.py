from __future__ import annotations

from keyring import get_keyring
from keyring.errors import NoKeyringError

from ..credentials import CredentialRecord
from ..exceptions import CondaAuthError
from .base import Storage
from .keyring import KeyringStorage


def get_storage_backend() -> Storage:
    """
    Determine the correct storage backend to use, raise CondaAuthError if none found.

    TODO: Add future support for another storage backend when keyring cannot be used.
    """
    try:
        keyring_tester = get_keyring()
        # Retrieve a dummy password to try to trigger NoKeyringError
        keyring_tester.get_password("conda_auth", "test")
    except NoKeyringError:
        raise CondaAuthError(
            "Unable to find a credential storage backend, which means this operating system"
            " is likely unsupported. One way to overcome this is by installing a third party"
            " keyring storage backend. You can find more information about that here: "
            "https://pypi.org/project/keyring"
        )

    return KeyringStorage()


class LazyStorage(Storage):
    """
    Resolve credential storage only when credentials are accessed.
    """

    def __init__(self) -> None:
        self._storage: Storage | None = None

    @property
    def backend(self) -> Storage:
        if self._storage is None:
            self._storage = get_storage_backend()

        return self._storage

    def set_credential(self, record: CredentialRecord) -> None:
        return self.backend.set_credential(record)

    def get_credential(self, target: str) -> CredentialRecord | None:
        return self.backend.get_credential(target)

    def delete_credential(self, target: str) -> None:
        return self.backend.delete_credential(target)


storage = LazyStorage()
