# conda-auth

A conda plugin for handling authenticated access to private channels.

conda-auth currently supports the following types of authentication:

- HTTP Basic Authentication
- bearer/header token authentication
- OAuth 2.0/OIDC user login
- HTTP proxy username/password authentication

On top of this, conda-auth supports session management via subcommands for logging into services (`conda auth login`), logging out of services (`conda auth logout`), and showing redacted credential status (`conda auth status`).

## Installation

conda-auth is available on conda-forge. As with all conda plugins, this must be installed into your base environment:
```
conda install --name base --channel conda-forge conda-auth
```

## Usage

**Log in** to a channel protected by HTTP basic authentication:

```
conda auth login https://example.com/my-protected-channel --basic
```

**Log in** to an anaconda.org channel with a token:

```
conda auth login https://example.com/my-protected-channel --token
```

**Log in** to a channel with a custom token header:

```
conda auth login https://example.com/my-protected-channel --token --header X-Auth --token-template 'Token {token}'
```

Add `--verify` to a login command to best-effort probe channel metadata before
reporting success. conda-auth prefers the smaller sharded repodata index and falls
back to `repodata.json`. Clear auth failures such as `401` or `403` roll back the
stored credential; missing or unreachable metadata is treated as inconclusive.

**Log in** to a channel with OAuth 2.0/OIDC:

```
conda auth login https://repo.example.com/private --oauth2 \
  --oauth-issuer-url https://idp.example.com \
  --oauth-client-id my-client
```

**Log in** to an HTTP proxy without storing the password in `.condarc`:

```
conda auth proxy login http --proxy-url http://proxy.example.com:8080 --username "$PROXY_USER"
```

**Log out** of a channel to remove credentials from your computer:

```
conda auth logout https://example.com/my-protected-channel
```

The login commands prompt for secrets by default. Passing passwords or tokens directly
on the command line is supported for non-interactive automation, but may expose them in
shell history or process listings.

conda-auth sends credentials only to HTTP(S) channel services. HTTPS is required for
remote channels by default. For an explicitly trusted plaintext HTTP channel, opt in
per channel:

```
conda auth login http://example.com/my-protected-channel --basic --allow-plaintext-http
```

Plaintext HTTP sends credentials without transport encryption. Prefer HTTPS whenever
possible.

Conda's `s3://` support currently uses boto3's normal AWS credential chain. conda-auth
does not set process-wide AWS environment variables for S3 credentials.

For more details about storage, platform behavior, and common workflows, see the
[user FAQ](docs/user/faq.md).

## Contributing to This Project

Contributions are very welcome to this project!

Feel free to:
1. File bug reports
2. Create feature requests
3. Open pull requests to resolve issues available in the [Github issues queue](https://github.com/conda-incubator/conda-auth/issues).
4. Review open pull requests
5. Report any typos, wrong/outdated information on the [documentation website](https://conda-incubator.github.io/conda-auth/).
6. Engage in ongoing discussions in this project and add new ideas.

Head to the [Developers Guide](https://conda-incubator.github.io/conda-auth/dev/) for this project to learn how to set up your development environment.

Do join the [conda Matrix chat](https://app.element.io/#/room/#conda:matrix.org) to get in touch with the rest of conda community and post any questions that you might have.

Happy Contributing!
