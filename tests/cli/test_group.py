import pytest

from conda_auth.cli import auth


def test_auth_wrapper():
    """
    Test to make sure the ``auth_wrapper`` function works.

    It is run with no arguments which will print the help message and raise a ``SystemExit``
    exception.
    """
    with pytest.raises(SystemExit):
        auth([])
