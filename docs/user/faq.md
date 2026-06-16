# Frequently asked questions

## Where should I install conda-auth?

Install conda-auth into the conda installation that runs your conda commands. For a
normal conda installation, that means the base environment:

```
conda install --name base --channel conda-forge conda-auth
```

Conda only discovers plugins from the environment running conda itself. Installing
conda-auth into a project environment does not make `conda auth` available to the base
conda command.

## Does conda-auth store secrets in `.condarc`?

No. Conda configuration stores non-secret metadata such as the auth type, auth target,
token header settings, and optional token file paths. Passwords, inline tokens, OAuth
refresh tokens, and proxy passwords are stored in the operating system keyring.

For `--token-file`, conda-auth stores only the file path in configuration and reads
the token value from that file when conda accesses the channel.

## Which authentication methods are supported?

conda-auth supports:

- HTTP basic authentication with username and password
- bearer or custom-header token authentication
- OAuth 2.0/OIDC user login with authorization-code and device-code flows
- HTTP proxy username/password authentication

Provider-specific commands such as `conda auth anaconda ...` or
`conda auth prefix ...` are not part of conda-auth. Use the generic endpoint and auth
mode options instead.

## What is the difference between channel authentication and proxy authentication?

Channel authentication proves access to the conda channel service itself. Use
`conda auth login <channel> ...` for private channels.

Proxy authentication proves access to an HTTP proxy between conda and the remote
service. Use `conda auth proxy login <proxy-key> ...` only when your conda traffic must
pass through an authenticated proxy.

## Should I use `--verify`?

Use `--verify` when you want login to fail immediately for clear authentication
rejections. conda-auth probes conda channel metadata after storing the credential. If
the channel returns `401` or `403`, conda-auth rolls back the stored credential and
auth configuration.

Verification is best-effort. Missing metadata, network failures, redirects, and server
errors are treated as inconclusive and do not fail login.

## Can I use plaintext HTTP?

Remote authenticated channels should use HTTPS. Plaintext HTTP sends credentials
without transport encryption.

For explicitly trusted plaintext HTTP channels, use `--allow-plaintext-http` on login.
The opt-in is scoped to that channel. Loopback HTTP, such as `localhost`, is allowed
for local test servers.

## Can I use S3, FTP, or file channels with conda-auth?

conda-auth only sends credentials to HTTP(S) channel services. FTP and file channels
are not supported by these auth handlers.

Conda's `s3://` support currently uses boto3's normal AWS credential chain, such as
environment variables, profiles, and instance credentials. conda-auth does not set AWS
environment variables for S3 credentials.

## Can I use conda-auth in automation?

Yes. The CLI supports `--json` for machine-readable output, and token/basic options
can be provided non-interactively. Be careful with secrets on command lines because
they may be visible in shell history or process listings. Prefer prompts or your
automation platform's secret injection when possible.

For Docker and CI systems that can mount secrets as files, prefer:

```
conda auth login <channel> --token-file /run/secrets/conda_auth_secret
```

This stores only the file path in conda configuration. The token is read at request
time, which avoids command-line exposure and does not require a writable keyring
backend. Use an absolute path to the mounted secret file. `/run/secrets` is accepted
by default.

## What does `conda auth status` show?

`conda auth status` shows redacted metadata for configured credentials. It does not
print passwords, bearer tokens, OAuth access tokens, or OAuth refresh tokens.

For token-file credentials, status shows that the credential source is `token_file`
without printing the token value.

## Will conda-auth migrate older keyring entries?

Yes, for configured HTTP basic and token channel credentials. Older conda-auth
versions stored one password-shaped keyring item per channel. Current conda-auth
stores one structured keyring record per auth target.

When a configured channel first needs credentials and no structured record exists,
conda-auth checks the old keyring item for that same target, writes the new structured
record, and best-effort deletes the old item. `conda auth logout` also attempts to
clean up matching old keyring items.

conda-auth cannot enumerate portable keyring contents, so it cannot automatically find
old orphaned credentials that are no longer referenced by conda configuration. Remove
those manually from your operating system keyring if needed.

## What if no keyring backend is available?

conda-auth requires a keyring backend for production secret storage. On desktop
systems this is usually provided by the operating system. On headless or minimal
systems, keyring may not find a secure backend.

Installing `keyrings.alt` can make a backend available, but its common file backend
stores secrets in plaintext. That is useful for tests and some constrained
environments, but it may not be acceptable for production usage.

For containerized token authentication, use `--token-file` with your container or CI
secret mount instead of a plaintext keyring fallback. By default, conda-auth only
accepts token files from `/run/secrets`. Set `CONDA_AUTH_TOKEN_FILE_ROOTS` only when
your container platform mounts secrets somewhere else.

## Did conda-auth lose my credentials after a Python update on macOS?

Usually no. The credentials normally remain in macOS Keychain, but the current Python
process may lose permission to read or delete them.

macOS Keychain may treat a new Python binary, such as one from a conda update or a
different conda environment, as a different application from the one that created the
Keychain item. When that happens, Keychain can prompt for approval, deny access, or
deny deletion.

If macOS shows a Keychain prompt, approve access for the Python or conda process you
are using. If no prompt appears, or access was denied, open Keychain Access, find the
`conda-auth` item, and either allow the current Python binary to access it or delete
the stale item and run `conda auth login` again.

When Keychain refuses deletion during `conda auth logout`, conda-auth removes the
user-visible conda auth configuration and warns that a stale Keychain item may remain.
