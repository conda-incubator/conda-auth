# conda-auth

A conda plugin for handling various HTTP based authentication schemes.

Conda auth is a plugin that handles various authentication schemes as well as
login session management. Currently, the following authentication schemes are
supported:

- HTTP Basic Authentication

On top of this, conda-auth supports session management via two subcommands
for logging into services (`conda auth login`) and logging out of services (`conda auth logout`).
