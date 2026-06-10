from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from conda import CondaError
from conda.gateways.connection.session import CondaSession
from conda.models.channel import Channel
from requests import Response
from requests.auth import AuthBase, HTTPBasicAuth
from requests.exceptions import RequestException

from .credentials import CredentialRecord
from .exceptions import CondaAuthError
from .handlers.basic_auth import HTTP_BASIC_AUTH_NAME
from .handlers.token import DEFAULT_TOKEN_HEADER, DEFAULT_TOKEN_TEMPLATE, TOKEN_NAME
from .oauth2_client import OAUTH2_NAME

AUTH_FAILURE_STATUS_CODES = frozenset((401, 403))
SHARDED_REPODATA_FILENAME = "repodata_shards.msgpack.zst"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
VERIFICATION_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class VerificationRequest:
    headers: dict[str, str]
    auth: VerificationAuth


@dataclass(frozen=True)
class AuthFailure:
    url: str
    status_code: int


class VerificationAuth(AuthBase):
    def __init__(self, auth: AuthBase | None = None) -> None:
        self.auth = auth
        self.channel_name = f"conda-auth-verify-{id(self)}"

    def __call__(self, r):
        if self.auth is None:
            return r
        return self.auth(r)


def verify_channel_credentials(
    channel: Channel,
    record: CredentialRecord,
    *,
    timeout: float = VERIFICATION_TIMEOUT_SECONDS,
) -> None:
    """
    Best-effort verification that stored credentials can access channel metadata.
    """
    request = build_verification_request(record)
    session = CondaSession(auth=request.auth)
    auth_failure = None
    probed = False

    for url in iter_verification_urls(channel):
        probed = True
        try:
            response = session.get(
                url,
                allow_redirects=False,
                headers=request.headers,
                timeout=timeout,
            )
        except (CondaError, RequestException):
            continue

        if 200 <= response.status_code < 300 and is_valid_metadata_response(url, response):
            return

        if response.status_code in AUTH_FAILURE_STATUS_CODES:
            auth_failure = AuthFailure(url=url, status_code=response.status_code)

    if auth_failure is not None:
        raise CondaAuthError(
            "Unable to verify credentials for "
            f"{channel.canonical_name!r}: {auth_failure.url!r} returned "
            f"HTTP {auth_failure.status_code}."
        )

    if not probed:
        return


def build_verification_request(record: CredentialRecord) -> VerificationRequest:
    if record.auth_type == HTTP_BASIC_AUTH_NAME:
        if record.username is None or record.password is None:
            raise CondaAuthError("Unable to verify incomplete HTTP basic credentials.")
        return VerificationRequest(
            headers={},
            auth=VerificationAuth(HTTPBasicAuth(record.username, record.password)),
        )

    if record.auth_type == TOKEN_NAME:
        if record.token is None:
            raise CondaAuthError("Unable to verify missing token credentials.")
        header = record.token_header or DEFAULT_TOKEN_HEADER
        template = record.token_template or DEFAULT_TOKEN_TEMPLATE
        return VerificationRequest(
            headers={header: template.format(token=record.token)},
            auth=VerificationAuth(),
        )

    if record.auth_type == OAUTH2_NAME:
        if record.access_token is None:
            raise CondaAuthError("Unable to verify missing OAuth 2.0 access token.")
        return VerificationRequest(
            headers={"Authorization": f"Bearer {record.access_token}"},
            auth=VerificationAuth(),
        )

    raise CondaAuthError(f"Unable to verify unsupported authentication type {record.auth_type!r}.")


def is_valid_metadata_response(url: str, response: Response) -> bool:
    if url.endswith(f"/{SHARDED_REPODATA_FILENAME}"):
        return response.content.startswith(ZSTD_MAGIC)

    if url.endswith("/repodata.json"):
        return is_repodata_response(response)

    if url.endswith("/channeldata.json"):
        return is_channeldata_response(response)

    return False


def is_repodata_response(response: Response) -> bool:
    try:
        data = response.json()
    except ValueError:
        return False

    return isinstance(data, dict) and (
        isinstance(data.get("packages"), dict)
        or isinstance(data.get("packages.conda"), dict)
        or data.get("repodata_version") is not None
    )


def is_channeldata_response(response: Response) -> bool:
    try:
        data = response.json()
    except ValueError:
        return False

    return isinstance(data, dict) and (
        data.get("channeldata_version") is not None or isinstance(data.get("packages"), dict)
    )


def iter_verification_urls(channel: Channel) -> Iterator[str]:
    """
    Yield common conda channel metadata URLs for verification probes.
    """
    seen = set()

    def add(url: str | None) -> Iterator[str]:
        if url is None or "*" in url or not url.startswith(("http://", "https://")):
            return
        if url in seen:
            return
        seen.add(url)
        yield url

    repodata_base_urls = sorted(
        (url.rstrip("/") for url in channel.urls()),
        key=lambda url: (not url.endswith("/noarch"), url),
    )
    for base_url in repodata_base_urls:
        yield from add(f"{base_url}/{SHARDED_REPODATA_FILENAME}")

    for base_url in repodata_base_urls:
        yield from add(f"{base_url}/repodata.json")

    if channel.base_url is not None:
        yield from add(f"{channel.base_url.rstrip('/')}/channeldata.json")
