from __future__ import annotations

import argparse
import sys
from contextlib import suppress
from copy import deepcopy
from getpass import getpass
from typing import Literal

from conda.base.context import context
from conda.cli.condarc import ConfigurationFile
from conda.common.serialize import yaml
from conda.exceptions import CondaError
from conda.models.channel import Channel

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..exceptions import CondaAuthError
from ..handlers import (
    HTTP_BASIC_AUTH_NAME,
    OAUTH2_NAME,
    TOKEN_NAME,
    AuthManager,
    basic_auth_manager,
    oauth2_auth_manager,
    token_auth_manager,
)
from ..handlers.base import allows_plaintext_http, find_channel_settings, validate_secure_channel
from ..handlers.token import (
    TOKEN_FILE_PARAM_NAME,
    TOKEN_HEADER_PARAM_NAME,
    TOKEN_PARAM_NAME,
    TOKEN_TEMPLATE_PARAM_NAME,
)
from ..oauth2_client import perform_oauth_login, revoke_oauth_record, with_target
from ..storage import storage
from ..verification import verify_channel_credentials
from .config import remove_channel_settings, update_channel_settings
from .oauth2 import build_oauth_login_config
from .parser import PROMPT_VALUE

AUTH_MANAGER_MAPPING = {
    HTTP_BASIC_AUTH_NAME: basic_auth_manager,
    TOKEN_NAME: token_auth_manager,
    OAUTH2_NAME: oauth2_auth_manager,
}


def login_from_args(args: argparse.Namespace) -> None:
    """Validate generic login arguments and execute login."""
    token = args.token
    token_file = args.token_file
    basic = args.basic
    oauth2 = args.oauth2
    auth_from_settings = None
    channel = Channel(args.channel)
    channel_settings = find_channel_settings(context.channel_settings, channel)
    configured_auth_value = channel_settings.get("auth") if channel_settings else None
    configured_auth = (
        configured_auth_value.strip().lower() if isinstance(configured_auth_value, str) else None
    )

    if not any((basic, token is not None, token_file is not None, oauth2)):
        auth_from_settings = configured_auth
        if configured_auth == OAUTH2_NAME:
            oauth2 = True
        elif configured_auth == HTTP_BASIC_AUTH_NAME:
            basic = True
        elif configured_auth == TOKEN_NAME:
            if channel_settings is None or not isinstance(
                channel_settings.get(TOKEN_FILE_PARAM_NAME), str
            ):
                token = PROMPT_VALUE
        else:
            raise CondaAuthError("Missing option 'basic' / 'token' / 'oauth2'.")

    if basic:
        selected_auth = HTTP_BASIC_AUTH_NAME
    elif token is not None or token_file is not None or auth_from_settings == TOKEN_NAME:
        selected_auth = TOKEN_NAME
    else:
        selected_auth = OAUTH2_NAME

    if selected_auth != HTTP_BASIC_AUTH_NAME and (
        args.username is not None or args.password is not None
    ):
        raise CondaAuthError("Options 'username' and 'password' can only be used with 'basic'")

    if selected_auth != TOKEN_NAME and (
        args.token_header is not None or args.token_template is not None
    ):
        raise CondaAuthError("Token header options can only be used with 'token'")

    validate_secure_channel(
        channel,
        allow_plaintext_http=args.allow_plaintext_http
        or (configured_auth == selected_auth and allows_plaintext_http(channel_settings)),
    )

    if token is PROMPT_VALUE:
        token = getpass("Token: ")

    oauth_client_secret = args.oauth_client_secret
    if oauth_client_secret is PROMPT_VALUE:
        oauth_client_secret = getpass("OAuth client secret: ")
    oauth_output_stream = sys.stderr if args.json else None

    if basic:
        username = args.username
        password = args.password

        if username is None:
            username = input("Username: ")
        if password is None:
            password = getpass("Password: ")

        login(
            channel,
            auth=auth_from_settings,
            basic=True,
            username=username,
            password=password,
            auth_allow_plaintext_http=args.allow_plaintext_http,
            verify=args.verify,
        )
        return

    login(
        channel,
        auth=auth_from_settings,
        token=token,
        token_file=token_file,
        oauth2=oauth2,
        oauth_issuer_url=args.oauth_issuer_url,
        oauth_client_id=args.oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_flow=args.oauth_flow,
        oauth_scopes=args.oauth_scopes,
        oauth_redirect_uri=args.oauth_redirect_uri,
        user_agent=args.user_agent,
        oauth_output_stream=oauth_output_stream,
        token_header=args.token_header,
        token_template=args.token_template,
        auth_allow_plaintext_http=args.allow_plaintext_http,
        verify=args.verify,
    )


def get_auth_manager(
    auth: str | None = None,
    basic: bool | None = None,
    token: str | Literal[False] | None = None,
    token_file: str | None = None,
    oauth2: bool | None = None,
    **kwargs,
) -> tuple[str, AuthManager]:
    """Return the auth manager selected by configuration or CLI options."""
    if auth:
        auth = auth.strip().lower()
    elif basic:
        auth = HTTP_BASIC_AUTH_NAME
    elif token is not None or token_file is not None:
        auth = TOKEN_NAME
    elif oauth2:
        auth = OAUTH2_NAME
    else:
        raise CondaAuthError("Missing authentication type.")

    if not (auth_manager := AUTH_MANAGER_MAPPING.get(auth)):
        raise CondaAuthError(
            f"Invalid authentication type. Valid types are: {set(AUTH_MANAGER_MAPPING)}"
        )

    return auth, auth_manager


def login(channel: Channel, **kwargs):
    """Log in to a channel by configuring and storing its credentials."""
    auth_type, auth_manager = get_auth_manager(**kwargs)
    configured_settings = find_channel_settings(context.channel_settings, channel)
    configured_auth_value = configured_settings.get("auth") if configured_settings else None
    configured_auth = (
        configured_auth_value.strip().lower() if isinstance(configured_auth_value, str) else None
    )

    user_config = ConfigurationFile.from_user_condarc()
    try:
        original_user_content = deepcopy(user_config.content)
        user_channel_settings = user_config.content.get("channel_settings", []) or []
        if not isinstance(user_channel_settings, list):
            raise CondaAuthError("Expected 'channel_settings' to be a list")
    except (CondaError, OSError, yaml.YAMLError) as exc:
        raise CondaAuthError(str(exc))

    user_settings = find_channel_settings(user_channel_settings, channel)
    user_auth_value = user_settings.get("auth") if user_settings else None
    user_auth = user_auth_value.strip().lower() if isinstance(user_auth_value, str) else None
    external_auth = configured_auth is not None and user_auth != configured_auth
    if external_auth and configured_auth != auth_type:
        raise CondaAuthError(
            f"Channel settings require authentication type {configured_auth!r}, "
            f"which cannot be overridden with {auth_type!r}."
        )

    auth_settings = configured_settings if configured_auth == auth_type else None
    allow_plaintext_http = allows_plaintext_http(kwargs) or allows_plaintext_http(auth_settings)
    verify = bool(kwargs.get("verify"))
    channel_setting = channel.canonical_name
    configured_target = auth_settings.get("auth_target") if auth_settings else None
    credential_target = (
        configured_target if isinstance(configured_target, str) else channel_setting
    )
    validate_secure_channel(channel, allow_plaintext_http=allow_plaintext_http)

    record = None
    username: str | None = None
    secret: str | None = None
    extra_params: dict[str, object] = {}
    persisted_settings: dict[str, object] = {}
    if auth_type == OAUTH2_NAME:
        oauth_config = build_oauth_login_config(
            channel,
            kwargs,
            channel_settings=auth_settings,
        )
        record = with_target(perform_oauth_login(oauth_config), credential_target)
    else:
        extra_params = {
            param: kwargs.get(param)
            for param in auth_manager.get_config_parameters()
            if kwargs.get(param) is not None
        }
        if auth_type == TOKEN_NAME and auth_settings is not None:
            for param in (
                TOKEN_FILE_PARAM_NAME,
                TOKEN_HEADER_PARAM_NAME,
                TOKEN_TEMPLATE_PARAM_NAME,
            ):
                if param not in extra_params and auth_settings.get(param) is not None:
                    extra_params[param] = auth_settings[param]
        persisted_settings = {
            key: value
            for key, value in extra_params.items()
            if key not in (TOKEN_PARAM_NAME, "password", "username")
        }
        extra_params["auth_target"] = credential_target
        if allow_plaintext_http:
            extra_params[AUTH_ALLOW_PLAINTEXT_HTTP_PARAM] = True
        username, secret = auth_manager.fetch_secret(channel, extra_params, use_cache=False)

    has_runtime_override = allows_plaintext_http(kwargs) or (
        auth_type == TOKEN_NAME
        and any(
            kwargs.get(param) is not None
            for param in (
                TOKEN_FILE_PARAM_NAME,
                TOKEN_HEADER_PARAM_NAME,
                TOKEN_TEMPLATE_PARAM_NAME,
            )
        )
    )
    wrote_user_condarc = False
    if not external_auth or has_runtime_override:
        try:
            with user_config as config:
                update_channel_settings(
                    config,
                    channel_setting,
                    auth_type,
                    None,
                    auth_target=credential_target,
                    allow_plaintext_http=allow_plaintext_http,
                    settings=persisted_settings,
                )
                wrote_user_condarc = True
        except (CondaError, OSError, yaml.YAMLError) as exc:
            auth_manager.cache_clear(channel.canonical_name)
            raise CondaAuthError(str(exc))

    stored_record = None
    verification_record = None
    try:
        if record is not None:
            storage.set_credential(record)
            stored_record = record
            verification_record = record
        elif username is not None and secret is not None:
            credential_record = auth_manager.save_credentials(
                channel,
                username,
                secret,
                allow_plaintext_http=allow_plaintext_http,
                target=credential_target,
                settings=extra_params,
            )
            verification_record = credential_record
            if not isinstance(extra_params.get(TOKEN_FILE_PARAM_NAME), str):
                stored_record = credential_record

        if verify and verification_record is not None:
            verify_channel_credentials(channel, verification_record)
    except Exception as credential_error:
        auth_manager.cache_clear(channel.canonical_name)
        rollback_error = None
        if wrote_user_condarc:
            try:
                with ConfigurationFile.from_user_condarc() as config:
                    config.content.clear()
                    config.content.update(original_user_content)
            except (CondaError, OSError, yaml.YAMLError) as exc:
                rollback_error = exc
        if stored_record is not None:
            if stored_record.auth_type == OAUTH2_NAME:
                with suppress(Exception):
                    revoke_oauth_record(stored_record)
            with suppress(Exception):
                storage.delete_credential(stored_record.target)
        if rollback_error is not None:
            raise CondaAuthError(
                f"{credential_error}. Failed to roll back channel settings: {rollback_error}"
            ) from credential_error
        raise


def logout(channel: Channel):
    """Log out of a channel and remove its stored credentials."""
    settings = find_channel_settings(context.channel_settings, channel)
    has_channel_settings = settings is not None
    if settings is None:
        record = storage.get_credential(channel.canonical_name)
        if record is None:
            raise CondaAuthError("Unable to find information about logged in session.")
        settings = {"auth": record.auth_type, "auth_target": record.target}
        if record.username is not None:
            settings["username"] = record.username

    configured_auth = settings.get("auth")
    _, auth_manager = get_auth_manager(
        auth=configured_auth if isinstance(configured_auth, str) else None
    )

    if has_channel_settings:
        try:
            user_config = ConfigurationFile.from_user_condarc()
            removed_auth_settings = remove_channel_settings(user_config, channel.canonical_name)
            if removed_auth_settings:
                with user_config:
                    pass
            elif auth_manager.get_credential_record(channel, settings) is None:
                raise CondaAuthError("No stored credential was found for the configured channel.")
        except (CondaError, OSError, yaml.YAMLError) as exc:
            raise CondaAuthError(str(exc))

    auth_manager.remove_secret(channel, settings)
    auth_manager.cache_clear(channel.canonical_name)
