from __future__ import annotations

import argparse

from conda.cli.helpers import add_parser_json

PROMPT_VALUE = object()


def add_basic_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-u",
        "--username",
        help="Username to use for private channels using HTTP basic authentication",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Password to use for private channels using HTTP basic authentication",
    )


def add_plaintext_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-plaintext-http",
        action="store_true",
        help="Allow credentials to be used over plaintext HTTP for this channel",
    )


def configure_parser(parser: argparse.ArgumentParser) -> None:
    """
    Configure the conda auth subcommand parser.
    """
    parser.set_defaults(parser=parser)
    subparsers = parser.add_subparsers(dest="command")

    login_parser = subparsers.add_parser(
        "login",
        help="Log in to a channel",
        description="Log in to a channel by storing the credentials or tokens associated with it",
    )
    login_parser.add_argument("channel")
    auth_options = login_parser.add_mutually_exclusive_group()
    auth_options.add_argument(
        "-b",
        "--basic",
        action="store_true",
        help="Save login credentials as HTTP basic authentication",
    )
    auth_options.add_argument(
        "-t",
        "--token",
        nargs="?",
        const=PROMPT_VALUE,
        metavar="TOKEN",
        help="Token to use for private channels using an API token",
    )
    add_basic_options(login_parser)
    add_plaintext_option(login_parser)
    add_parser_json(login_parser)
    login_parser.set_defaults(parser=login_parser)

    logout_parser = subparsers.add_parser(
        "logout",
        help="Log out of a channel",
        description="Log out of a channel by removing any credentials or tokens associated with it",
    )
    logout_parser.add_argument("channel")
    add_parser_json(logout_parser)

    status_parser = subparsers.add_parser(
        "status",
        help="Show stored credentials",
        description="Show redacted stored credential metadata",
    )
    status_parser.add_argument("channel", nargs="?")
    add_parser_json(status_parser)


def build_parser(prog_name: str = "conda auth") -> argparse.ArgumentParser:
    """
    Build a standalone parser for tests and direct invocation.
    """
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description="Commands for handling authentication within conda",
    )
    configure_parser(parser)
    return parser
