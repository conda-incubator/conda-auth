from __future__ import annotations

import keyring
from keyring.errors import PasswordDeleteError

from ..exceptions import CondaAuthError
from .base import Storage


class KeyringStorage(Storage):
    """
    Storage implementation for keyring library
    """

    def get_password(self, key_id: str, username: str) -> str | None:
        return keyring.get_password(key_id, username)

    def set_password(self, key_id: str, username: str, password: str) -> None:
        return keyring.set_password(key_id, username, password)

    def delete_password(self, key_id: str, username: str) -> None:
        try:
            return keyring.delete_password(key_id, username)
        except PasswordDeleteError as exc:
            raise CondaAuthError(f"Unable to remove secret: {exc}")
