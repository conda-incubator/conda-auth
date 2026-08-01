from __future__ import annotations

from collections.abc import Mapping

from conda.cli.condarc import ConfigurationFile

from ..constants import AUTH_ALLOW_PLAINTEXT_HTTP_PARAM
from ..exceptions import CondaAuthError
from ..oauth2_client import (
    OAUTH_CLIENT_ID_PARAM_NAME,
    OAUTH_CLIENT_SECRET_PARAM_NAME,
    OAUTH_FLOW_PARAM_NAME,
    OAUTH_ISSUER_URL_PARAM_NAME,
    OAUTH_REDIRECT_URI_PARAM_NAME,
    OAUTH_SCOPE_PARAM_NAME,
    OAUTH_USER_AGENT_PARAM_NAME,
)

# Keys that hold actual credentials or session state.  These are cleared from
# the user's channel_settings on logout so that secrets are never left behind.
AUTH_CREDENTIAL_KEYS = frozenset(
    (
        "auth_target",
        "username",
        "password",
        "token",
        OAUTH_CLIENT_SECRET_PARAM_NAME,
    )
)

# Keys that hold channel *configuration* (auth type and public OAuth params).
AUTH_CONFIG_KEYS = frozenset(
    (
        "auth",
        OAUTH_ISSUER_URL_PARAM_NAME,
        OAUTH_CLIENT_ID_PARAM_NAME,
        OAUTH_FLOW_PARAM_NAME,
        OAUTH_SCOPE_PARAM_NAME,
        OAUTH_REDIRECT_URI_PARAM_NAME,
        OAUTH_USER_AGENT_PARAM_NAME,
        AUTH_ALLOW_PLAINTEXT_HTTP_PARAM,
    )
)

# Combined set for callers that need both at once (backwards compat).
AUTH_CHANNEL_SETTING_KEYS = AUTH_CREDENTIAL_KEYS | AUTH_CONFIG_KEYS


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
    Replace the credential-owned settings for a single channel.

    Non-credential keys (including auth-configuration keys such as
    ``auth``, ``oauth_client_id``, etc.) that were already present in the
    existing entry are preserved so that manually-configured OAuth parameters
    survive a login round-trip.
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
        # Preserve everything except the credential keys — this intentionally
        # keeps auth-config keys (oauth_client_id, oauth_flow, etc.) so they
        # are not lost when the user re-logs-in after a logout.
        updated_settings.update(
            {
                key: value
                for key, value in channel_settings[last_channel_index].items()
                if key not in AUTH_CREDENTIAL_KEYS
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
    Remove the user's channel credential settings via conda's configuration
    file API.

    Only ``AUTH_CREDENTIAL_KEYS`` (passwords, tokens, session state) are
    stripped.  Auth-configuration keys (``auth``, ``oauth_client_id``,
    ``oauth_flow``, etc.) are intentionally preserved so that subsequent
    ``conda auth login <url>`` invocations can still auto-detect the auth
    type without requiring the user to pass flags or re-install a
    resource-handler package.

    The entry is kept in ``channel_settings`` as long as it contains at least
    one key beyond ``channel`` itself (e.g. ``auth`` or an OAuth param).  An
    entry that would reduce to ``{channel: ...}`` with no other keys is
    removed entirely.
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

        # Strip only credential keys; preserve auth-config keys.
        updated_settings = {
            key: value for key, value in settings.items() if key not in AUTH_CREDENTIAL_KEYS
        }

        # Only drop the entry if it has nothing useful left (just the channel
        # key itself).  Entries that still carry auth-config data are kept so
        # the next login can auto-detect the auth type.
        if updated_settings != {"channel": channel}:
            updated_channel_settings.append(updated_settings)

    config.content["channel_settings"] = updated_channel_settings
    return removed_auth_settings
