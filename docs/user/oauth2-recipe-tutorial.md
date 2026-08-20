# Creating an OAuth 2.0 auth recipe

This tutorial shows how operators of a channel with OAuth 2.0 can create a conda package
that pre-configures `channel_settings` for their own channel. Once their users install
the package, they can authenticate with a single command:

```
conda install example-oauth2-config
conda auth login https://repo.example.com
```

This simplifies OAuth 2.0 authentication and authorization without requiring users to
configure each option themselves. Do not put client secrets or access tokens in this
configuration package.

## The `channel_settings` format

`conda-auth` reads OAuth 2.0 configuration from the `channel_settings` key in the
conda configuration (condarc). The package we'll create will end up with a
conda configuration file with the following fields:

```yaml
channel_settings:
  - channel: https://repo.example.com         # URL of your protected channel
    auth: oauth2                               # tells conda-auth to use OAuth 2.0

    oauth_client_id: <your-public-client-id>  # required, issued by your IdP

    # Optional, defaults to the channel URL if omitted.
    # Set this if your IdP lives at a different host than the channel.
    oauth_issuer_url: https://idp.example.com

    # Optional, defaults to "auto".
    # "auto"        : tries browser login first, falls back to device-code
    # "auth-code"   : browser login with PKCE (requires a desktop environment)
    # "device-code" : headless login for SSH / CI environments
    oauth_flow: device-code

    # Optional, list of OAuth scopes to request.
    oauth_scopes:
      - profile

    # Optional, only needed for auth-code flow.
    # oauth_redirect_uri: http://localhost:8765/callback
```

## Creating the conda recipe

### Directory layout

```
resource-handler-auth/
|-- recipe.yaml
`-- resource-handler-auth.yaml    # the channel_settings condarc
```

### `resource-handler-auth.yaml`

Write your `channel_settings` block here (see the format above):

```yaml
channel_settings:
  - channel: https://repo.example.com
    auth: oauth2
    oauth_client_id: xxxxxxxxxxxxxxxxxxxxxx
    oauth_issuer_url: https://idp.example.com
    oauth_flow: device-code
    oauth_scopes:
      - openid
```

### `recipe.yaml`

```yaml
package:
  name: example-oauth2-config
  version: 1.0.0

build:
  number: 0
  noarch: generic
  script: |
    mkdir -p "${PREFIX}/condarc.d"
    cp resource-handler-auth.yaml \
       "${PREFIX}/condarc.d/resource-handler-auth.yaml"

requirements:
  run:
    - conda-auth

about:
  summary: conda-auth configuration for resource.example.com
  license: MIT
```

The target directory `$PREFIX/condarc.d/` is the standard
per-environment condarc merge location. conda automatically merges all
`*.yaml` files in that directory into the effective configuration for the
active environment.

:::{note}
The `run` dependency on `conda-auth` ensures that the plugin is installed
alongside your config package.

You should always install this package to the base environment so it's available
across the installation:

```bash
conda install --name base example-oauth2-config
```
:::

## Testing locally

Build the package and install it into a test environment:

```bash
# Build
rattler-build build --recipe resource-handler-auth/recipe.yaml

# Install into the base environment (required for conda plugins)
conda install --name base --use-local example-oauth2-config

# Verify the settings were merged
conda config --show channel_settings
```

You should see your `channel_settings` entry in the output. Then test the
full login flow:

```bash
conda auth login https://repo.example.com
```

If the configuration is correct, the OAuth 2.0 flow starts immediately with no
additional flags required.

To clean up:

```bash
conda auth logout https://repo.example.com
conda remove --name base example-oauth2-config
```

## End-user experience

Once you have published your package, your users only need two commands:

```bash
# 1. Install conda-auth and your config package
conda install --name base example-oauth2-config

# 2. Log in with no OAuth flags required
conda auth login https://repo.example.com
```

`conda-auth` reads the `channel_settings` from the installed config and
initiates the OAuth 2.0 flow automatically. After a successful login, all
subsequent `conda install` or `conda search` commands against
`https://repo.example.com` are authenticated transparently.
