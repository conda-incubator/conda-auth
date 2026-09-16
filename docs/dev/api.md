# Prepare authentication for a configuration transaction

`conda_auth.api` separates credential acquisition from configuration persistence.
An application can complete an authentication flow, review the resulting public settings, and include those settings in a larger configuration edit.
The existing `conda auth login` command continues to configure the user file immediately.

## Select the target

Pass a native conda `ConfigurationFile` to select the target before preparing authentication.
Its user, system, environment, and explicit path factories are supported.
The API reads that target but does not mutate its content or write a file.

```python
from conda.cli.condarc import ConfigurationFile
from conda.models.channel import Channel
from conda_auth.api import prepare_login

configuration = ConfigurationFile.from_env_condarc(prefix="/path/to/environment")
result = prepare_login(
    Channel("https://repo.example.com/research"),
    configuration=configuration,
    oauth2=True,
    oauth_issuer_url="https://idp.example.com",
    oauth_client_id="application-client",
)
```

`prepare_login` accepts the existing login function's authentication options.
Basic, token, mounted token file, and OAuth modes use the same auth managers, credential store, transport validation, and optional credential verification as the CLI.
Invalid combinations are rejected before credentials are read.
Pass `interactive=True` to let conda-auth collect missing basic credentials or a token on a terminal.
Transport and inherited authentication rules are validated before prompting.
The API does not print its result.
Never log the input options, which may contain secrets.

## Apply the proposed fields

`LoginPreparation.configuration_edit` is either `None` when inherited authentication configuration needs no edit, or a mapping with:

| Field | Meaning |
| --- | --- |
| `channel` | Exact channel setting to update |
| `set` | Auth-owned nonsecret fields and their proposed values |
| `unset` | Auth-owned fields to remove from the selected entry |

Apply the edit to the last exact matching `channel_settings` entry in the selected source, creating an entry if absent.
Preserve unrelated fields, earlier matching rules, and other configuration entries.
The caller owns source precedence, policy validation, concurrency checks, cancellation, and the eventual commit.
Do not replace all `channel_settings` with this one entry.

`plan_channel_settings(configuration, channel, auth_type, **options)` returns the same field edit without acquiring or storing credentials.
Its optional values are `auth_target`, `allow_plaintext_http`, and a mapping of public authentication `settings`.
Token, password, username, and OAuth client-secret values are not accepted in that settings mapping.
Authentication method changes remove obsolete auth-owned fields while leaving other provider data untouched.

## Keep credential and configuration state distinct

`LoginPreparation.credentials_state` is `stored` when conda-auth stored a credential, `external` for an externally supplied credential such as a mounted token file, or `unchanged` when no record was stored or obtained.
The edit never contains a password, token, or OAuth client secret.

Credential storage can complete before the caller commits configuration.
Cancelling the configuration edit does not delete the stored credential.
The credential remains owned by conda-auth and can be managed through its normal commands.
A failed optional verification uses the login flow's existing cleanup behavior and leaves the selected configuration unmodified.
