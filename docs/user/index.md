# Getting started

```{toctree}
:maxdepth: 1
:hidden:

FAQ <faq>
```

The `conda-auth` plugin improves the authentication experience for conda. Read below to learn how to start using it.

## Installation

The plugin is available on conda-forge and can be installed like any other conda package:

```
conda install -c conda-forge conda-auth
```

## Usage

Once installed the plugin makes authentication commands available under `conda auth`.
Use the generic commands for channel and proxy endpoints:

```
conda auth login <target>
conda auth logout <target>
conda auth status [target]

conda auth proxy login <proxy-key>
```

The plugin stores secrets in the operating system keyring. Conda configuration only
contains non-secret auth metadata such as the auth type and target.

### Credential verification

Login can optionally verify credentials by probing conda channel metadata paths:

```
conda auth login <channel_name> --basic --verify
```

Verification is best-effort. conda-auth prefers the smaller sharded repodata index,
then falls back to `repodata.json` and `channeldata.json`. If conda-auth can read
channel metadata, login succeeds. If the channel returns a clear authentication failure
such as `401` or `403`, login fails and rolls back the stored credential and auth
configuration. Missing metadata, network failures, redirects, and server errors are
treated as inconclusive and do not fail login.

### HTTP basic authentication

To log in to a channel using HTTP basic authentication, run the following command:

```
conda auth login <channel_name> --basic
```

Once this has been run, you will be prompted for your username and password.

For non-interactive automation, you can also specify username and password as command
options:

```
conda auth login <channel_name> --basic --username "$USERNAME" --password "$PASSWORD"
```

```{caution}
Passing passwords directly on the command line may expose them in shell history or
process listings. Prefer the prompt-based command when working interactively.
```

### Token authentication

Use `--token` for bearer/header token authentication:

```
conda auth login <channel_name> --token
```

You will then be prompted for your token. Optionally, you can specify the token value as
an option for non-interactive automation:

```
conda auth login <channel_name> --token <token_value>
```

```{caution}
Passing tokens directly on the command line may expose them in shell history or process
listings. Prefer the prompt-based command when working interactively.
```

The request handler sends this as `Authorization: Bearer <token>` and does not
overwrite an existing `Authorization` header.

For Docker, CI, and other headless environments, prefer a file-mounted secret over a
token passed on the command line:

```
conda auth login <channel_name> --token-file /run/secrets/conda_auth_secret
```

This stores only the token file path and non-secret token header metadata in condarc.
The token value is read from the file when conda accesses the channel, so this mode
does not require a writable keyring backend. A single trailing newline in the token
file is ignored, matching how many secret managers write mounted secrets, but empty or
multi-line token files are rejected. Token file paths must be absolute and are only
accepted from `/run/secrets` by default.

If your container platform mounts secrets somewhere else, set
`CONDA_AUTH_TOKEN_FILE_ROOTS` to that mounted secret root. Avoid using this override
for ordinary host filesystem paths.

For Docker builds, use a BuildKit secret mount instead of `ARG` or `ENV`:

```
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=conda_auth_secret \
    conda auth login <channel_name> --token-file /run/secrets/conda_auth_secret --verify \
 && conda install --override-channels -c <channel_name> <package_name> \
 && conda auth logout <channel_name>
```

For services that expect a different token header, customize the header name and
value template:

```
conda auth login <channel_name> --token <token_value> \
  --header X-Auth \
  --token-template 'Token {token}'
```

The token template must include `{token}`. The `--token-header` and
`--header-template` aliases are also accepted.

### Proxy authentication

Proxy credentials are separate from channel credentials. conda-auth can store proxy
usernames and passwords in keyring while keeping `proxy_servers` entries in condarc
free of embedded secrets:

```
conda auth proxy login http \
  --proxy-url http://proxy.example.com:8080 \
  --username "$PROXY_USER"
```

The `http` argument is the `proxy_servers` key conda uses. You can also use conda's
host-specific key form, such as `https://repo.example.com`. If `proxy_servers` is
already configured, `--proxy-url` can be omitted and conda-auth will store only the
credential:

```
conda auth proxy login http --username "$PROXY_USER"
```

Before conda network commands run, conda-auth hydrates the in-process proxy URL with
the stored credential. The password is not written to condarc.

Proxy URLs must use `http://` or `https://` and must not include embedded
credentials. Proxy credentials are scoped to both the `proxy_servers` key and the
proxy URL origin. If a proxy URL changes after login, pass the old URL with
`--proxy-url` when running `conda auth proxy logout` or `conda auth proxy status`.

```{caution}
Proxy authentication is not channel authentication. Use `conda auth login` for private
channels and `conda auth proxy login` only for the HTTP proxy between conda and the
remote service.
```

### OAuth 2.0/OIDC authentication

OAuth 2.0 is available for OIDC services that support discovery plus
authorization-code or device-code login flows:

```
conda auth login https://repo.example.com --oauth2 \
  --oauth-issuer-url https://idp.example.com \
  --oauth-client-id my-client \
  --oauth-flow auto
```

Supported OAuth 2.0 modes:

- `auto`: tries browser authorization-code login first, and falls back to device-code
  when the browser cannot be opened
- `auth-code`: browser login with a localhost callback and PKCE
- `device-code`: headless login for SSH and terminal-only environments

Additional OAuth options include `--oauth-client-secret`, repeatable
`--oauth-scope`, `--oauth-redirect-uri`, and `--user-agent`. conda-auth refreshes
OAuth 2.0 access tokens before expiry when a refresh token is available, and
attempts token revocation on logout when the OAuth server advertises a revocation
endpoint.

The password grant, implicit flow, and client credentials grant are not supported.

### Channel transports

conda-auth supports authenticated HTTP(S) channel services. Remote channels must use
HTTPS by default, and FTP and file channels are not supported by these auth handlers.

Conda's `s3://` support currently uses boto3's normal AWS credential chain, such as
environment variables, profiles, and instance credentials. conda-auth does not set
process-wide AWS environment variables. First-class channel-scoped S3 credentials
need a future conda-side S3 credential hook.

For an explicitly trusted plaintext HTTP channel, opt in per channel:

```
conda auth login http://example.com/my-protected-channel --basic --allow-plaintext-http
```

```{caution}
Plaintext HTTP sends credentials without transport encryption. Prefer HTTPS whenever
possible, and only use `--allow-plaintext-http` for endpoints you explicitly trust.
```

### Logging out of a channel

If you want to clear your user credentials from your computer for any reason, you can do so by
running the `conda auth logout` command. All you have to do is provide a channel name, and it
will find and remove your credentials from the password store and user conda configuration.

You can do this by running the following command:

```
conda auth logout <channel_name>
```

`login`, `logout`, and `status` support JSON output for automation:

```
conda auth login <channel_name> --token --json
conda auth logout <channel_name> --json
conda auth status --json
```

`status` output is redacted and does not print stored tokens, passwords, OAuth 2.0
access tokens, or refresh tokens.

### Credential storage

conda-auth relies on the [keyring](https://github.com/jaraco/keyring) package to store
passwords and secrets. Keyring is the only production write backend. conda-auth does
not add a plaintext auth file backend or implicit `.netrc` fallback.

#### Storage backend unavailable?

Because of this, it only supports a limited number of operating systems, mostly
desktop operating systems like Windows, macOS and several Linux variants.

If you want to use conda-auth, but are not using a supported operating system, you can install the
[keyring-alt](https://github.com/jaraco/keyrings.alt) package:

```
conda install -c conda-forge keyrings.alt
```

```{caution}
This method stores passwords and secrets in a plain text file on the filesystem and may not be acceptable for
production usage. Please read the [project's README](https://github.com/jaraco/keyrings.alt) for more
information.
```

For containerized token authentication, prefer `--token-file` with Docker or CI secret
mounts instead of adding a plaintext keyring fallback. By default, token files are
only accepted from `/run/secrets`.

For more storage and platform details, see the [FAQ](faq.md).

## Reporting bugs

Have you found a bug you want to let us know about? Please create an issue at our
[GitHub project](https://github.com/conda-incubator/conda-auth/issues/new/choose).

And thank you for helping us improve conda-auth!
