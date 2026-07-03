from conda_auth.cli import auth


def test_auth_wrapper(runner):
    """
    Test to make sure the ``auth_wrapper`` function works.

    It is run with no arguments which will print the help message.
    """
    result = runner.invoke(auth, [])

    assert result.exit_code == 0, result.output
    assert "Commands for handling authentication within conda" in result.output
