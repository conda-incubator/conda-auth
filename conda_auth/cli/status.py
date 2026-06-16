from __future__ import annotations

import argparse
from collections.abc import Mapping
from fnmatch import fnmatch

from conda.base.context import context
from conda.common.serialize import json
from conda.common.url import urlparse as conda_urlparse
from conda.models.channel import Channel

from ..handlers.token import TOKEN_FILE_PARAM_NAME, TOKEN_NAME
from ..storage import storage


def get_status_entries(target: str | None = None) -> list[dict[str, object]]:
    """
    Return redacted credential status entries.
    """
    entries = []
    for credential_target, settings in get_status_sources(target):
        if settings is not None and (
            entry := get_configured_status_entry(credential_target, settings)
        ):
            entries.append(entry)
            continue

        record = storage.get_credential(credential_target)
        if record is not None:
            entries.append(record.to_status_entry())
    return entries


def get_status_targets(target: str | None = None) -> tuple[str, ...]:
    """
    Return known configured credential targets for status output.
    """
    return tuple(credential_target for credential_target, _ in get_status_sources(target))


def get_status_sources(
    target: str | None = None,
) -> tuple[tuple[str, Mapping[str, object] | None], ...]:
    """
    Return known configured credential targets and their settings for status output.
    """
    seen = set()
    sources: list[tuple[str, Mapping[str, object] | None]] = []
    source_indexes: dict[str, int] = {}

    def add(candidate: str | None, settings: Mapping[str, object] | None = None) -> None:
        if candidate is not None and candidate not in seen:
            seen.add(candidate)
            source_indexes[candidate] = len(sources)
            sources.append((candidate, settings))
        elif candidate is not None and settings is not None:
            index = source_indexes[candidate]
            if sources[index][1] is None:
                sources[index] = (candidate, settings)

    requested_channel = Channel(target) if target is not None else None
    requested_keys = set()
    if target is not None and requested_channel is not None:
        requested_keys.update((target, requested_channel.canonical_name))
        add(target)
        add(requested_channel.canonical_name)

    for settings in context.channel_settings:
        if not isinstance(settings, Mapping) or not settings.get("auth"):
            continue

        configured_channel = settings.get("channel")
        if not isinstance(configured_channel, str):
            continue

        auth_target = settings.get("auth_target")
        if not isinstance(auth_target, str):
            auth_target = configured_channel

        if requested_channel is None:
            add(auth_target, settings)
        elif status_setting_matches_target(
            configured_channel,
            auth_target,
            requested_channel,
            requested_keys,
        ):
            add(auth_target, settings)

    return tuple(sources)


def get_configured_status_entry(
    target: str,
    settings: Mapping[str, object],
) -> dict[str, object] | None:
    """
    Return status metadata for configured credentials that do not use secret storage.
    """
    if settings.get("auth") != TOKEN_NAME:
        return None
    if not isinstance(settings.get(TOKEN_FILE_PARAM_NAME), str):
        return None
    return {"target": target, "auth_type": TOKEN_NAME, "source": "token_file"}


def status_setting_matches_target(
    configured_channel: str,
    auth_target: str,
    requested_channel: Channel,
    requested_keys: set[str],
) -> bool:
    """
    Return whether a configured auth setting applies to an explicit status target.
    """
    return (
        configured_channel in requested_keys
        or auth_target in requested_keys
        or channel_matches(configured_channel, requested_channel)
        or channel_matches(auth_target, requested_channel)
    )


def channel_matches(configured_channel: str, channel: Channel) -> bool:
    """
    Match configured channel names the same way conda selects auth handlers.
    """
    if configured_channel == channel.canonical_name:
        return True

    parsed_channel = conda_urlparse(channel.base_url)
    parsed_setting = conda_urlparse(configured_channel)
    if parsed_setting.scheme != parsed_channel.scheme:
        return False

    channel_url = parsed_channel.netloc + parsed_channel.path
    pattern = parsed_setting.netloc + parsed_setting.path
    return fnmatch(channel_url, pattern)


def status(target: str | None = None) -> list[dict[str, object]]:
    """
    Return stored credential status entries.
    """
    return get_status_entries(target)


def output_status(args: argparse.Namespace, entries: list[dict[str, object]]) -> None:
    """
    Output credential status in text or JSON form.
    """
    if getattr(args, "json", False) is True:
        print(json.dumps({"success": True, "credentials": entries}))
        return

    if not entries:
        print("No credentials stored")
        return

    for entry in entries:
        target = entry.get("target", "<unknown>")
        auth_type = entry.get("auth_type", "<unknown>")
        expires_at = entry.get("expires_at")
        details = [f"{target}: {auth_type}"]
        if expires_at is not None:
            details.append(f"expires_at={expires_at}")
        print(" ".join(details))
