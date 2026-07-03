from __future__ import annotations

import argparse
from contextlib import suppress
from getpass import getpass

from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import json, yaml
from conda.exceptions import CondaError

from ..constants import SUCCESSFUL_LOGIN_MESSAGE, SUCCESSFUL_LOGOUT_MESSAGE
from ..exceptions import CondaAuthError
from ..proxy import ProxyAuthManager
from ..storage import storage
from .config import update_proxy_server
from .status import output_status


def auth_proxy_command(args: argparse.Namespace) -> None:
    """
    Dispatch proxy-specific auth commands.
    """
    if args.proxy_command is None:
        raise CondaAuthError("Missing proxy command.")

    if args.proxy_command == "login":
        login_proxy_from_args(args)
        if args.json:
            print(json.dumps({"success": True, "message": SUCCESSFUL_LOGIN_MESSAGE}))
        else:
            print(SUCCESSFUL_LOGIN_MESSAGE)
        return

    if args.proxy_command == "logout":
        logout_proxy_from_args(args)
        if args.json:
            print(json.dumps({"success": True, "message": SUCCESSFUL_LOGOUT_MESSAGE}))
        else:
            print(SUCCESSFUL_LOGOUT_MESSAGE)
        return

    if args.proxy_command == "status":
        proxy_manager = ProxyAuthManager()
        output_status(
            args,
            proxy_manager.status_entries(args.proxy_key, proxy_url=args.proxy_url),
        )
        return

    raise CondaAuthError(f"Unknown proxy command: {args.proxy_command}")


def login_proxy_from_args(args: argparse.Namespace) -> None:
    """
    Store proxy credentials and optionally configure proxy_servers.
    """
    proxy_manager = ProxyAuthManager()
    proxy_url = proxy_manager.resolve_url(args.proxy_key, args.proxy_url)
    assert proxy_url is not None

    username = args.username
    password = args.password
    if username is None:
        username = input("Proxy username: ")
    if password is None:
        password = getpass("Proxy password: ")

    missing = object()
    previous_proxy_servers = missing
    proxy_config_updated = False
    if args.proxy_url is not None:
        try:
            with ConfigurationFile.from_user_condarc() as config:
                previous_proxy_servers = config.content.get("proxy_servers", missing)
                update_proxy_server(config, args.proxy_key, proxy_url)
                proxy_config_updated = True
        except (CondaError, OSError, yaml.YAMLError) as exc:
            raise CondaAuthError(str(exc))

    try:
        storage.set_credential(
            proxy_manager.create_record(args.proxy_key, proxy_url, username, password)
        )
    except Exception:
        if proxy_config_updated:
            with suppress(Exception), ConfigurationFile.from_user_condarc() as config:
                if previous_proxy_servers is missing:
                    config.content.pop("proxy_servers", None)
                else:
                    config.content["proxy_servers"] = previous_proxy_servers
        raise


def logout_proxy_from_args(args: argparse.Namespace) -> None:
    """
    Remove stored proxy credentials.
    """
    proxy_manager = ProxyAuthManager()
    proxy_url = proxy_manager.resolve_url(args.proxy_key, args.proxy_url)
    assert proxy_url is not None
    storage.delete_credential(proxy_manager.target(args.proxy_key, proxy_url))
