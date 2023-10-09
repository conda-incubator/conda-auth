# flake8: noqa: F401
from keyring import get_keyring
from keyring.errors import NoKeyringError

from .base import Storage
from .keyring import KeyringStorage
from ..exceptions import CondaAuthError


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


storage = get_storage_backend()
