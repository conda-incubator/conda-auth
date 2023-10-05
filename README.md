# conda-auth

A conda plugin for handling various HTTP based authentication schemes.

Conda auth is a plugin that handles various authentication schemes as well as login session management. Currently, the following authentication schemes are supported:

- HTTP Basic Authentication

On top of this, conda-auth supports session management via two subcommands for logging into services (conda auth login) and logging out of services (conda auth logout).

## Installation
To start using conda auth, we recommend installing to your base environment:

```
conda install --name base --channel conda-forge conda-auth
```

## Why conda-auth?

Currently when using conda, if you want use a channel that requires the use of HTTP Basic Authentication, you need to store your user credentials in your `.condarc` file:

```
channels:
  - https://username:password@example.com/channel
```

The example above has one primary problem: storing credentials in clear text. This is a practice that is frowned upon generally and one we should avoid if possible.

The conda-auth project aims to solve this problem by storing credentials in an encrypted and password protected manner. This is accomplished by introducing a dependency on the [keyring project](https://github.com/jaraco/keyring). This Python library uses the underlying secret store mechanism for many types of desktop operating systems, including Windows, OSX and Linux.

Using this plugin will then ensure that users are storing their user credentials in a safer manner.

## How to Contribute to this project?
Contributions are very welcome to this project! 

Feel free to:
1. File bug reports
2. Create feature requests
3. Open pull requests fixing bugs, or adding new features
4. Review open pull requests
5. Engage in ongoing discussions in this project and add new ideas.

Do join the [conda Matrix chat](https://app.element.io/#/room/#conda:matrix.org) to get in touch with the rest of conda community and post any questions that you might have. 
