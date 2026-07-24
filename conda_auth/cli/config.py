from __future__ import annotations

from collections.abc import Mapping

from conda.cli.condarc import ConfigurationFile

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..exceptions import CondaAuthError

AUTH_CHANNEL_SETTING_KEYS = frozenset(
    (
        "auth",
        "auth_target",
        "username",
        "password",
        "token",
        AUTH_ALLOW_PLAINTEXT_HTTP_PARAM,
    )
)


def get_updated_channel_settings(
    channel_settings: list,
    channel: str,
    auth_type: str,
    username: str | None = None,
    *,
    auth_target: str | None = None,
    allow_plaintext_http: bool = False,
) -> list:
    """
    Replace the auth-owned settings for a single channel.
    """
    updated_settings: dict[str, object] = {"channel": channel}
    last_channel_index = next(
        (
            index
            for index, settings in reversed(list(enumerate(channel_settings)))
            if isinstance(settings, Mapping) and settings.get("channel") == channel
        ),
        None,
    )
    if last_channel_index is not None:
        updated_settings.update(
            {
                key: value
                for key, value in channel_settings[last_channel_index].items()
                if key not in AUTH_CHANNEL_SETTING_KEYS
            }
        )

    updated_settings["auth"] = auth_type
    updated_settings["auth_target"] = auth_target or channel
    if username is not None:
        updated_settings["username"] = username
    if allow_plaintext_http:
        updated_settings[AUTH_ALLOW_PLAINTEXT_HTTP_PARAM] = True

    if last_channel_index is None:
        return [*channel_settings, updated_settings]

    return [
        updated_settings if index == last_channel_index else settings
        for index, settings in enumerate(channel_settings)
    ]


def update_channel_settings(
    config: ConfigurationFile,
    channel: str,
    auth_type: str,
    username: str | None = None,
    *,
    auth_target: str | None = None,
    allow_plaintext_http: bool = False,
) -> None:
    """
    Update the user's channel auth settings via conda's configuration file API.
    """
    channel_settings = config.content.get("channel_settings", []) or []
    if not isinstance(channel_settings, list):
        raise CondaAuthError("Expected 'channel_settings' to be a list")

    config.content["channel_settings"] = get_updated_channel_settings(
        channel_settings,
        channel,
        auth_type,
        username,
        auth_target=auth_target,
        allow_plaintext_http=allow_plaintext_http,
    )


def remove_channel_settings(config: ConfigurationFile, channel: str) -> bool:
    """
    Remove the user's channel auth settings via conda's configuration file API.
    """
    channel_settings = config.content.get("channel_settings", []) or []
    if not isinstance(channel_settings, list):
        raise CondaAuthError("Expected 'channel_settings' to be a list")

    removed_auth_settings = False
    updated_channel_settings = []
    for settings in channel_settings:
        if not isinstance(settings, Mapping) or settings.get("channel") != channel:
            updated_channel_settings.append(settings)
            continue

        removed_auth_settings = removed_auth_settings or any(
            key in settings for key in AUTH_CHANNEL_SETTING_KEYS
        )
        updated_settings = {
            key: value for key, value in settings.items() if key not in AUTH_CHANNEL_SETTING_KEYS
        }
        if updated_settings != {"channel": channel}:
            updated_channel_settings.append(updated_settings)

    config.content["channel_settings"] = updated_channel_settings
    return removed_auth_settings
