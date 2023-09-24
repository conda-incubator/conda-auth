# conda-auth

A conda plugin for ensuring that user credentials are not compromised while using conda channels requiring HTTP Basic Authentication and OAuth Authentication.

## Why conda-auth?

Currently when using conda, if you want use a channel that requires the use of HTTP Basic Authentication, you need to store your user credentials in your `.condarc` file:

```
channels:
  - https://username:password@example.com/channel
```

The example above has one primary problem: storing credentials in clear text. This is a practice that is frowned upon generally and one we should avoid if possible.

The conda-auth project aims to solve this problem by storing credentials in an encrypted and password protected manner. This is accomplished by introducing a dependency on the [keyring project](https://github.com/jaraco/keyring). This Python library uses the underlying secret store mechanism for many types of desktop operating systems, including Windows, OSX and Linux.

Using this plugin will then ensure that users are storing their user credentials in a safer manner.

## Installation
Instructions about how to install this plugin and set it up to work with conda

## How to Contribute to this project?
Instructions about forking the project, and start contributing. 
