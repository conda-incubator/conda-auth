from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlsplit, urlunsplit

from conda.base.context import context
from conda.gateways.connection.session import CondaSession
from frozendict import frozendict

from .constants import PROXY_AUTH_NAME
from .credentials import CredentialRecord
from .exceptions import CondaAuthError

CredentialGetter = Callable[[str], CredentialRecord | None]
PROXY_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


@dataclass(frozen=True)
class ProxyURL:
    """
    Helper for proxy URL validation, normalization, and secret-safe formatting.
    """

    raw: str

    @property
    def parsed(self):
        return urlsplit(self.raw)

    @property
    def has_credentials(self) -> bool:
        """
        Return whether the proxy URL already carries username and password.
        """
        parsed = self.parsed
        return parsed.username is not None or parsed.password is not None

    @property
    def origin(self) -> str:
        """
        Return a normalized proxy URL origin suitable for credential scoping.
        """
        self.validate()
        parsed = self.parsed
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
        host = (parsed.hostname or "").lower()
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme.lower()}://{host}:{port}"

    def with_credentials(self, username: str, password: str) -> str:
        """
        Return a proxy URL with percent-encoded username and password.
        """
        self.validate()
        parsed = self.parsed
        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}"
        port = f":{parsed.port}" if parsed.port is not None else ""
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{userinfo}@{host}{port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    def redacted(self) -> str:
        """
        Return a proxy URL with any embedded username and password removed.
        """
        parsed = self.parsed
        if parsed.username is None and parsed.password is None:
            return self.raw

        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            port = ""
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        return urlunsplit(
            (parsed.scheme, f"{host}{port}", parsed.path, parsed.query, parsed.fragment)
        )

    def validate(self) -> None:
        """
        Validate a conda proxy_servers URL.
        """
        parsed = self.parsed
        if not parsed.scheme or not parsed.hostname:
            raise CondaAuthError("Proxy URL must include a scheme and host")
        if parsed.scheme not in {"http", "https"}:
            raise CondaAuthError("Proxy URL scheme must be 'http' or 'https'")
        try:
            parsed.port
        except ValueError as exc:
            raise CondaAuthError("Proxy URL port is invalid") from exc
        if parsed.username is not None or parsed.password is not None:
            raise CondaAuthError("Proxy URL must not include credentials")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise CondaAuthError("Proxy URL must not include a path, query, or fragment")


class ProxyAuthManager:
    """
    Manage proxy credentials stored outside conda configuration.
    """

    auth_name = PROXY_AUTH_NAME
    target_prefix = "proxy"

    def target(self, proxy_key: str, proxy_url: str) -> str:
        """
        Return the credential storage target for a conda proxy_servers key and URL.
        """
        self.validate_key(proxy_key)
        return f"{self.target_prefix}:{proxy_key}:{ProxyURL(proxy_url).origin}"

    def validate_key(self, proxy_key: str) -> None:
        """
        Validate a conda proxy_servers key.
        """
        if "://" in proxy_key:
            parsed = urlsplit(proxy_key)
            if (
                parsed.scheme
                and parsed.hostname
                and parsed.path in ("", "/")
                and not parsed.query
                and not parsed.fragment
            ):
                return
            raise CondaAuthError("Proxy key must be a scheme or scheme://hostname value")

        if not PROXY_KEY_PATTERN.fullmatch(proxy_key):
            raise CondaAuthError("Proxy key must be a scheme or scheme://hostname value")

    def create_record(
        self,
        proxy_key: str,
        proxy_url: str,
        username: str,
        password: str,
    ) -> CredentialRecord:
        """
        Build the structured credential record for a proxy credential.
        """
        return CredentialRecord(
            target=self.target(proxy_key, proxy_url),
            auth_type=self.auth_name,
            username=username,
            password=password,
        )

    def get_credential(self, target: str) -> CredentialRecord | None:
        """
        Return a proxy credential record if one is available.
        """
        from .storage import storage

        try:
            return storage.get_credential(target)
        except CondaAuthError:
            return None

    def resolve_url(
        self,
        proxy_key: str,
        proxy_url: str | None = None,
        *,
        proxy_servers: Mapping[str, object] | None = None,
        raise_if_missing: bool = True,
    ) -> str | None:
        """
        Return the configured proxy URL for a key, or validate an explicit URL.
        """
        self.validate_key(proxy_key)
        if proxy_servers is None:
            proxy_servers = context.proxy_servers

        candidate_url: object = proxy_url
        if candidate_url is None:
            candidate_url = proxy_servers.get(proxy_key)
        if candidate_url is None:
            if raise_if_missing:
                raise CondaAuthError(
                    "Missing proxy URL. Use --proxy-url or configure proxy_servers."
                )
            return None
        if not isinstance(candidate_url, str):
            if raise_if_missing:
                raise CondaAuthError("Proxy URL must be text")
            return None

        try:
            ProxyURL(candidate_url).validate()
        except CondaAuthError:
            if raise_if_missing:
                raise
            return None
        return candidate_url

    def status_entries(
        self,
        proxy_key: str | None = None,
        proxy_url: str | None = None,
        *,
        proxy_servers: Mapping[str, object] | None = None,
        credential_getter: CredentialGetter | None = None,
    ) -> list[dict[str, object]]:
        """
        Return status entries for stored proxy credentials.
        """
        if proxy_key is None and proxy_url is not None:
            raise CondaAuthError("Proxy URL status requires a proxy key.")

        if proxy_servers is None:
            proxy_servers = context.proxy_servers
        if credential_getter is None:
            from .storage import storage

            credential_getter = storage.get_credential

        proxy_keys = (proxy_key,) if proxy_key is not None else tuple(proxy_servers)
        entries = []
        for candidate in proxy_keys:
            candidate_url = self.resolve_url(
                candidate,
                proxy_url if candidate == proxy_key else None,
                proxy_servers=proxy_servers,
                raise_if_missing=False,
            )
            if candidate_url is None:
                continue

            candidate_proxy = ProxyURL(candidate_url)
            if candidate_proxy.has_credentials:
                continue

            record = credential_getter(self.target(candidate, candidate_url))
            if record is not None:
                entry = record.to_status_entry()
                entry["proxy_url"] = candidate_proxy.redacted()
                entries.append(entry)
        return entries

    def add_credentials(
        self,
        proxy_servers: Mapping[str, object],
        *,
        credential_getter: CredentialGetter | None = None,
    ) -> dict[str, object]:
        """
        Return a proxy_servers copy with stored credentials added where available.
        """
        get_credential = credential_getter or self.get_credential
        hydrated = dict(proxy_servers)
        for proxy_key, proxy_url in proxy_servers.items():
            if not isinstance(proxy_key, str) or not isinstance(proxy_url, str):
                continue

            proxy = ProxyURL(proxy_url)
            if proxy.has_credentials:
                continue

            try:
                target = self.target(proxy_key, proxy_url)
            except CondaAuthError:
                continue

            record = get_credential(target)
            if record is None or record.username is None or record.password is None:
                continue

            hydrated[proxy_key] = proxy.with_credentials(record.username, record.password)

        return hydrated

    def apply_to_context(
        self,
        *,
        credential_getter: CredentialGetter | None = None,
    ) -> None:
        """
        Add stored proxy credentials to conda's resolved proxy settings for this process.
        """
        proxy_servers = context.proxy_servers
        if not proxy_servers:
            return

        hydrated = self.add_credentials(
            proxy_servers,
            credential_getter=credential_getter,
        )
        if hydrated == dict(proxy_servers):
            return

        # conda does not expose a public proxy credential hook yet. Updating the
        # resolved configuration cache keeps secrets out of .condarc while using
        # conda's existing proxy URL machinery for requests.
        context._cache_["proxy_servers"] = frozendict(hydrated)
        CondaSession.cache_clear()
