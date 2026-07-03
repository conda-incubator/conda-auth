from __future__ import annotations

import argparse

from conda.common.serialize import json
from conda.models.channel import Channel

from ..constants import (
    PROXY_COMMAND_NAME,
    SUCCESSFUL_LOGIN_MESSAGE,
    SUCCESSFUL_LOGOUT_MESSAGE,
)
from ..exceptions import CondaAuthError
from .channel import login_from_args, logout
from .parser import build_parser, configure_parser
from .proxy import auth_proxy_command
from .status import output_status
from .status import status as get_status

__all__ = (
    "auth",
    "build_parser",
    "configure_parser",
)


def output_success(args: argparse.Namespace, message: str) -> None:
    """
    Output a successful command result.
    """
    if getattr(args, "json", False) is True:
        print(json.dumps({"success": True, "message": message}))
    else:
        print(message)


def auth(args: argparse.Namespace | None = None) -> None:
    """
    The conda auth subcommand.
    """
    if args is None:
        parser = build_parser()
        args = parser.parse_args()

    if args.command is None:
        args.parser.print_help()
        return

    if args.command == "login":
        login_from_args(args)
        output_success(args, SUCCESSFUL_LOGIN_MESSAGE)
        return

    if args.command == "logout":
        logout(Channel(args.channel))
        output_success(args, SUCCESSFUL_LOGOUT_MESSAGE)
        return

    if args.command == "status":
        output_status(args, get_status(args.channel))
        return

    if args.command == PROXY_COMMAND_NAME:
        auth_proxy_command(args)
        return

    raise CondaAuthError(f"Unknown command: {args.command}")
