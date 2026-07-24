import pytest

from conda_auth.credentials import CredentialRecord


@pytest.mark.parametrize(
    ("values", "expected_scopes", "expected_username", "expected_expires_at"),
    (
        (
            {"scopes": ["channel:read", 1], "username": 123, "expires_at": 3600},
            ("channel:read", "1"),
            "123",
            3600,
        ),
        (
            {"scopes": ("channel:read", 1), "expires_at": "3600"},
            ("channel:read", "1"),
            None,
            3600,
        ),
        (
            {"scopes": "channel:read", "expires_at": "later"},
            (),
            None,
            None,
        ),
        (
            {"expires_at": []},
            (),
            None,
            None,
        ),
    ),
    ids=("list-values", "tuple-values", "invalid-strings", "invalid-type"),
)
def test_credential_record_from_dict_normalizes_values(
    values,
    expected_scopes,
    expected_username,
    expected_expires_at,
):
    record = CredentialRecord.from_dict(
        {
            "target": "tester",
            "auth_type": "token",
            **values,
        }
    )

    assert record.scopes == expected_scopes
    assert record.username == expected_username
    assert record.expires_at == expected_expires_at
