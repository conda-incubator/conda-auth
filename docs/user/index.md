# Getting started

The `conda-auth` plugin improves the authentication experience for conda. Read below to learn how to start using it.

## Installation

The plugin is available on conda-forge and can be installed like any other conda package:

```
conda install -c conda-forge conda-auth
```

## Usage

Once installed the plugin makes two new commands available: `conda auth login` and `conda auth logout`. The plugin
supports various types of authentication schemes. Read below to learn how to use each.

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

The following examples are for authenticating with channels using token based authentication.

For [anaconda.org](https://anaconda.org) channels:

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
`--oauth-scope`, `--oauth-redirect-uri`, and `--user-agent`. Conda auth refreshes
OAuth 2.0 access tokens before expiry when a refresh token is available, and
attempts token revocation on logout when the OAuth server advertises a revocation
endpoint.

The password grant, implicit flow, and client credentials grant are not supported.

### Channel transports

Conda auth supports authenticated HTTP(S) channel services. Remote channels must use
HTTPS by default, and FTP and file channels are not supported by these auth handlers.

Conda's `s3://` support currently uses boto3's normal AWS credential chain, such as
environment variables, profiles, and instance credentials. Conda auth does not set
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

Both `login` and `logout` support JSON output for automation:

```
conda auth login <channel_name> --token --json
conda auth logout <channel_name> --json
```

`status` output is redacted and does not print stored tokens, passwords, OAuth 2.0
access tokens, or refresh tokens.

### Storage backend unavailable?

Conda auth relies on the [keyring](https://github.com/jaraco/keyring) package to store its passwords and secrets.
Because of this, it only supports a limited number of operating systems, mostly desktop operating systems like
Windows, OSX and several Linux variants.

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

## Reporting bugs

Have you found a bug you want to let us know about? Please create an issue at our
[GitHub project](https://github.com/conda-incubator/conda-auth/issues/new/choose).

And thank you for helping us improve conda auth!
