import pytest
from keyring.errors import NoKeyringError

from conda_auth.exceptions import CondaAuthError
from conda_auth.storage import get_storage_backend


def test_no_available_storage_backend(keyring):
    """
    Test to make sure we've covered the lines where an exception is raise
    if no storage backend can be found.
    """
    _, get_keyring_mock = keyring(None)

    get_keyring_mock.side_effect = NoKeyringError()

    with pytest.raises(
        CondaAuthError, match="Unable to find a credential storage backend"
    ):
        get_storage_backend()
