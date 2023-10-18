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

You also have the ability to specify username and password as command options:

```
conda auth login <chanel_name> --basic --username $USERNAME --password $PASSWORD
```

### Token authentication

The following examples are for authenticating with channels using token based authentication.

For [anaconda.org](https://anaconda.org) channels:

```
conda auth login <channel_name> --token
```

You will then be prompted for your token. Optionally, you can specify the token value as
an option:

```
conda auth login <channel_name> --token <token_value>
```

For other channels not hosted at anaconda.org, use the full URL of the channel:

```
conda auth login https://example.com/my-protected-channel --token
```

### Logging out of a channel

If you want to clear you user credentials from your computer for any reason, you can do so by
running the `conda auth logout` command. All you have to do is provide a channel name, and it
will find and remove your credentials from the password store.

You can do this by running the following command:

```
conda auth logout <channel_name>
```

## Reporting bugs

Have you found a bug you want to let us know about? Please create an issue at our
[GitHub project](https://github.com/conda-incubator/conda-auth/issues/new/choose).

And thank you for helping us improve conda auth!
