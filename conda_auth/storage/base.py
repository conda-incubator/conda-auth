from __future__ import annotations

from abc import ABC, abstractmethod

from ..credentials import CredentialRecord


class Storage(ABC):
    """ABC class for all credential storage backends"""

    @abstractmethod
    def set_credential(self, record: CredentialRecord) -> None:
        """
        Store a structured credential record.
        """

    @abstractmethod
    def get_credential(self, target: str) -> CredentialRecord | None:
        """
        Return a structured credential record for a target.
        """

    @abstractmethod
    def delete_credential(self, target: str) -> None:
        """
        Delete a structured credential record for a target.
        """
