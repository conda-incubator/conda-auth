from __future__ import annotations

import argparse

from conda.cli.helpers import add_parser_json

from ..constants import PROXY_COMMAND_NAME
from ..handlers.token import (
    TOKEN_FILE_PARAM_NAME,
    TOKEN_HEADER_PARAM_NAME,
    TOKEN_TEMPLATE_PARAM_NAME,
)
from ..oauth2_client import OAUTH_SCOPE_PARAM_NAME

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


def add_oauth_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--oauth-issuer-url", help="OIDC issuer URL")
    parser.add_argument("--oauth-client-id", help="OAuth client ID")
    parser.add_argument(
        "--oauth-client-secret",
        nargs="?",
        const=PROMPT_VALUE,
        metavar="SECRET",
        help="OAuth client secret for confidential clients",
    )
    parser.add_argument(
        "--oauth-flow",
        choices=("auto", "auth-code", "device-code"),
        default="auto",
        help="OAuth flow to use",
    )
    parser.add_argument(
        "--oauth-scope",
        dest=OAUTH_SCOPE_PARAM_NAME,
        action="append",
        default=[],
        help="OAuth scope to request. May be supplied multiple times",
    )
    parser.add_argument("--oauth-redirect-uri", help="OAuth redirect URI")
    parser.add_argument("--user-agent", help="User-Agent header for OAuth requests")


def add_token_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--header",
        "--token-header",
        dest=TOKEN_HEADER_PARAM_NAME,
        metavar="HEADER",
        help="HTTP header name to use for token authentication",
    )
    parser.add_argument(
        "--token-template",
        "--header-template",
        dest=TOKEN_TEMPLATE_PARAM_NAME,
        metavar="TEMPLATE",
        help="Header value template. Must include '{token}'",
    )


def add_plaintext_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--allow-plaintext-http",
        action="store_true",
        help="Allow credentials to be used over plaintext HTTP for this channel",
    )


def add_verify_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify credentials by probing channel metadata before reporting success",
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
        help="Bearer token to use in the Authorization header",
    )
    auth_options.add_argument(
        "--token-file",
        dest=TOKEN_FILE_PARAM_NAME,
        metavar="PATH",
        help="Read bearer token from a mounted secret file, under /run/secrets by default",
    )
    auth_options.add_argument(
        "--oauth2",
        action="store_true",
        help="Use OAuth 2.0/OIDC authentication",
    )
    add_basic_options(login_parser)
    add_token_options(login_parser)
    add_oauth_options(login_parser)
    add_plaintext_option(login_parser)
    add_verify_option(login_parser)
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

    proxy_parser = subparsers.add_parser(
        PROXY_COMMAND_NAME,
        help="Authenticate with configured proxy servers",
    )
    proxy_subparsers = proxy_parser.add_subparsers(dest="proxy_command")
    proxy_login = proxy_subparsers.add_parser("login", help="Log in to a proxy server")
    proxy_login.add_argument("proxy_key", help="proxy_servers key, for example 'http'")
    proxy_login.add_argument(
        "--proxy-url",
        help="Proxy URL to store in proxy_servers without credentials",
    )
    add_basic_options(proxy_login)
    add_parser_json(proxy_login)

    proxy_logout = proxy_subparsers.add_parser("logout", help="Log out of a proxy server")
    proxy_logout.add_argument("proxy_key", help="proxy_servers key, for example 'http'")
    proxy_logout.add_argument(
        "--proxy-url",
        help="Proxy URL for the stored credential. Defaults to configured proxy_servers",
    )
    add_parser_json(proxy_logout)

    proxy_status = proxy_subparsers.add_parser("status", help="Show proxy credentials")
    proxy_status.add_argument("proxy_key", nargs="?")
    proxy_status.add_argument(
        "--proxy-url",
        help="Proxy URL for the stored credential. Defaults to configured proxy_servers",
    )
    add_parser_json(proxy_status)


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
