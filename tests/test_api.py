from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import yaml
from conda.models.channel import Channel

from conda_auth.api import plan_channel_settings, prepare_login
from conda_auth.credentials import CredentialRecord
from conda_auth.exceptions import CondaAuthError
from conda_auth.storage import storage

CHANNEL = "https://repo.example.com/research"


@pytest.fixture(autouse=True)
def isolated_login_context(monkeypatch, context_factory):
    monkeypatch.setattr("conda_auth.cli.channel.context", context_factory())


@pytest.mark.parametrize("scope", ("user", "system", "environment", "file"))
@pytest.mark.parametrize("existing", (False, True), ids=("new-file", "existing-file"))
def test_prepare_login_preserves_selected_configuration_until_commit(
    tmp_path, monkeypatch, keyring, scope, existing
):
    target = tmp_path / ".condarc"
    monkeypatch.setattr("conda.base.context.user_rc_path", str(target))
    monkeypatch.setattr("conda.base.context.sys_rc_path", str(target))
    if scope == "user":
        configuration = ConfigurationFile.from_user_condarc()
    elif scope == "system":
        configuration = ConfigurationFile.from_system_condarc()
    elif scope == "environment":
        configuration = ConfigurationFile.from_env_condarc(prefix=tmp_path)
    else:
        configuration = ConfigurationFile(path=target)
    if existing:
        target.write_text("channels: [conda-forge]\nssl_verify: true\n")
    original_bytes = target.read_bytes() if existing else None
    original_content = deepcopy(configuration.content)
    keyring(None)

    result = prepare_login(Channel(CHANNEL), configuration=configuration, token="secret-token")

    assert configuration.content == original_content
    assert (target.read_bytes() if target.exists() else None) == original_bytes
    assert result.credentials_state == "stored"
    record = storage.get_credential(CHANNEL)
    assert record is not None
    assert record.token == "secret-token"
    assert "secret-token" not in repr(result)
    assert result.configuration_edit == {
        "channel": CHANNEL,
        "set": {"auth": "token", "auth_target": CHANNEL},
        "unset": [],
    }

    # The caller merges only the returned fields, then explicitly commits its target.
    edit = result.configuration_edit
    assert edit is not None
    configuration.content["channel_settings"] = [{"channel": edit["channel"], **edit["set"]}]
    assert (target.read_bytes() if target.exists() else None) == original_bytes
    configuration.write()
    assert yaml.read(path=target) == {
        **original_content,
        "channel_settings": [{"channel": CHANNEL, "auth": "token", "auth_target": CHANNEL}],
    }


def test_plan_channel_settings_returns_only_auth_owned_edits(keyring):
    backend, _ = keyring(None)
    configuration = ConfigurationFile(
        content={
            "channels": ["conda-forge"],
            "channel_settings": [
                {"channel": CHANNEL, "auth": "token", "description": "earlier"},
                {
                    "channel": CHANNEL,
                    "auth": "token",
                    "token": "legacy-secret",
                    "token_header": "X-Auth",
                    "ssl_verify": True,
                },
                {"channel": "https://elsewhere.example.com", "auth": "anaconda-auth"},
            ],
        }
    )
    original = deepcopy(configuration.content)

    edit = plan_channel_settings(configuration, CHANNEL, "http-basic")

    assert edit == {
        "channel": CHANNEL,
        "set": {"auth": "http-basic", "auth_target": CHANNEL},
        "unset": ["token", "token_header"],
    }
    assert configuration.content == original
    assert backend.get_password_calls == []
    assert backend.set_password_calls == []
    assert "legacy-secret" not in repr(edit)


@pytest.mark.parametrize("secret_key", ("token", "password", "username", "oauth_client_secret"))
def test_plan_rejects_secret_settings_without_mutation(keyring, secret_key):
    backend, _ = keyring(None)
    configuration = ConfigurationFile(content={})

    with pytest.raises(CondaAuthError, match="Only public authentication settings"):
        plan_channel_settings(configuration, CHANNEL, "token", settings={secret_key: "secret"})

    assert configuration.content == {}
    assert backend.set_password_calls == []


@pytest.mark.parametrize("settings", ("invalid", {"auth": "token"}))
def test_prepare_rejects_invalid_config_before_storing_credentials(keyring, settings):
    backend, _ = keyring(None)
    configuration = ConfigurationFile(content={"channel_settings": settings})

    with pytest.raises(CondaAuthError, match="Expected 'channel_settings' to be a list"):
        prepare_login(Channel(CHANNEL), configuration=configuration, token="secret-token")

    assert configuration.content == {"channel_settings": settings}
    assert backend.set_password_calls == []


@pytest.mark.parametrize(
    "options",
    (
        {"basic": True, "token": "secret"},
        {"auth": "http-basic", "token": "secret"},
        {"token": "secret", "password": "secret"},
        {"basic": True, "token_header": "X-Auth"},
        {"token": "secret", "shell": "echo secret"},
    ),
)
def test_prepare_rejects_invalid_options_before_credentials(keyring, options):
    backend, _ = keyring(None)
    configuration = ConfigurationFile(content={})

    with pytest.raises(CondaAuthError):
        prepare_login(Channel(CHANNEL), configuration=configuration, **options)

    assert configuration.content == {}
    assert backend.get_password_calls == []
    assert backend.set_password_calls == []


def test_prepare_uses_selected_target_public_settings(keyring):
    keyring(None)
    content = {
        "channel_settings": [
            {
                "channel": CHANNEL,
                "auth": "token",
                "auth_target": "shared-login",
                "token_header": "X-Auth",
                "token_template": "Token {token}",
            }
        ]
    }
    configuration = ConfigurationFile(content=deepcopy(content))

    result = prepare_login(Channel(CHANNEL), configuration=configuration, token="secret-token")

    assert configuration.content == content
    assert result.configuration_edit is not None
    assert result.configuration_edit["set"] == {
        "auth": "token",
        "auth_target": "shared-login",
        "token_header": "X-Auth",
        "token_template": "Token {token}",
    }
    record = storage.get_credential("shared-login")
    assert record is not None
    assert record.token == "secret-token"


def test_prepare_preserves_inherited_auth_configuration(monkeypatch, context_factory, keyring):
    keyring(None)
    monkeypatch.setattr(
        "conda_auth.cli.channel.context",
        context_factory(
            channel_settings=[
                {
                    "channel": "https://repo.example.com/*",
                    "auth": "token",
                    "auth_target": "shared-login",
                }
            ]
        ),
    )
    configuration = ConfigurationFile(content={})

    result = prepare_login(Channel(CHANNEL), configuration=configuration, token="secret-token")

    assert result.configuration_edit is None
    assert result.credentials_state == "stored"
    assert configuration.content == {}
    record = storage.get_credential("shared-login")
    assert record is not None
    assert record.token == "secret-token"


def test_prepare_oauth_reuses_login_and_keeps_secrets_in_provider(monkeypatch, keyring):
    keyring(None)
    received = []

    def perform_login(config):
        received.append(config)
        return CredentialRecord(
            target="",
            auth_type="oauth2",
            username="oauth2",
            access_token="access-secret",
            refresh_token="refresh-secret",
            client_id="client",
            token_endpoint="https://idp.example.com/token",
        )

    monkeypatch.setattr("conda_auth.cli.channel.perform_oauth_login", perform_login)
    configuration = ConfigurationFile(content={})
    result = prepare_login(
        Channel(CHANNEL),
        configuration=configuration,
        oauth2=True,
        oauth_client_id="client",
        oauth_issuer_url="https://idp.example.com",
        oauth_client_secret="client-secret",
    )

    assert received[0].client_secret == "client-secret"
    assert result.credentials_state == "stored"
    assert configuration.content == {}
    record = storage.get_credential(CHANNEL)
    assert record is not None
    assert record.access_token == "access-secret"
    assert "secret" not in repr(result)


def test_prepare_verification_failure_leaves_config_unchanged(monkeypatch, keyring):
    keyring(None)
    configuration = ConfigurationFile(content={"channels": ["conda-forge"]})

    def fail_verification(channel, record):
        raise CondaAuthError("Could not verify credentials")

    monkeypatch.setattr("conda_auth.cli.channel.verify_channel_credentials", fail_verification)
    with pytest.raises(CondaAuthError, match="Could not verify credentials"):
        prepare_login(
            Channel(CHANNEL),
            configuration=configuration,
            token="secret-token",
            verify=True,
        )

    assert configuration.content == {"channels": ["conda-forge"]}
    assert storage.get_credential(CHANNEL) is None


@pytest.mark.parametrize("auth_type", ("http-basic", "token"))
def test_prepare_interactive_credentials_stay_with_provider(monkeypatch, keyring, auth_type):
    keyring(None)
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda prompt: "user")
    monkeypatch.setattr("conda_auth.cli.channel.getpass", lambda prompt: "secret")
    configuration = ConfigurationFile(content={})

    result = prepare_login(
        Channel(CHANNEL),
        configuration=configuration,
        auth=auth_type,
        interactive=True,
    )

    assert result.configuration_edit is not None
    assert result.configuration_edit["set"]["auth"] == auth_type
    assert result.credentials_state == "stored"
    assert "secret" not in repr(result)
    assert configuration.content == {}


@pytest.mark.parametrize("channel", ("http://repo.example.com/research", "file:///channel"))
def test_prepare_rejects_insecure_transport_before_prompt(monkeypatch, keyring, channel):
    backend, _ = keyring(None)

    def fail_prompt(prompt):
        raise AssertionError("Credentials must not be requested")

    monkeypatch.setattr("conda_auth.cli.channel.getpass", fail_prompt)
    with pytest.raises(CondaAuthError, match="Refusing to use credentials"):
        prepare_login(
            Channel(channel),
            configuration=ConfigurationFile(content={}),
            auth="token",
            interactive=True,
        )

    assert backend.set_password_calls == []


def test_prepare_mounted_token_reports_external_state(tmp_path, monkeypatch, keyring):
    backend, _ = keyring(None)
    token_file = tmp_path / "token"
    token_file.write_text("mounted-secret\n")
    monkeypatch.setenv("CONDA_AUTH_TOKEN_FILE_ROOTS", str(tmp_path))
    configuration = ConfigurationFile(content={})

    result = prepare_login(
        Channel(CHANNEL), configuration=configuration, token_file=str(token_file)
    )

    assert result.credentials_state == "external"
    assert result.configuration_edit is not None
    assert result.configuration_edit["set"]["token_file"] == str(token_file)
    assert "mounted-secret" not in repr(result)
    assert configuration.content == {}
    assert backend.set_password_calls == []
