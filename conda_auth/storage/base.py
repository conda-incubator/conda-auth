from __future__ import annotations

from abc import ABC, abstractmethod


class Storage(ABC):
    """ABC class for all credential storage backends"""

    @abstractmethod
    def set_password(self, key_id: str, username: str, password: str) -> None:
        """
        Sets the password for a specific ``key_id``
        """

    @abstractmethod
    def get_password(self, key_id: str, username: str) -> str | None:
        """
        Gets the password for a specific ``key_id``
        """

    @abstractmethod
    def delete_password(self, key_id: str, username: str) -> None:
        """
        Deletes the password for a specific ``key_id``
        """
