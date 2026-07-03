from __future__ import annotations

from collections.abc import Mapping
from typing import TextIO, cast

from conda.models.channel import Channel

from ..exceptions import CondaAuthError
from ..oauth2_client import (
    OAUTH_CLIENT_ID_PARAM_NAME,
    OAUTH_CLIENT_SECRET_PARAM_NAME,
    OAUTH_FLOW_PARAM_NAME,
    OAUTH_ISSUER_URL_PARAM_NAME,
    OAUTH_REDIRECT_URI_PARAM_NAME,
    OAUTH_SCOPE_PARAM_NAME,
    OAUTH_USER_AGENT_PARAM_NAME,
    OAuthLoginConfig,
    scopes_from_value,
)


def ensure_url_scheme(target: str) -> str:
    """
    Default bare OAuth issuer hosts to HTTPS.
    """
    if "://" in target:
        return target
    return f"https://{target}"


def build_oauth_login_config(
    channel: Channel,
    options: Mapping[str, object],
) -> OAuthLoginConfig:
    """
    Build an OAuth login configuration from parsed CLI options.
    """
    issuer_url = options.get(OAUTH_ISSUER_URL_PARAM_NAME)
    client_id = options.get(OAUTH_CLIENT_ID_PARAM_NAME)
    scopes = scopes_from_value(options.get(OAUTH_SCOPE_PARAM_NAME))

    if issuer_url is None:
        issuer_url = channel.base_url

    if not isinstance(issuer_url, str):
        raise CondaAuthError("OAuth issuer URL not found")
    if not isinstance(client_id, str):
        raise CondaAuthError("OAuth client ID not found")

    flow = options.get(OAUTH_FLOW_PARAM_NAME) or "auto"
    if not isinstance(flow, str):
        raise CondaAuthError("OAuth flow must be text")

    client_secret = options.get(OAUTH_CLIENT_SECRET_PARAM_NAME)
    if client_secret is not None and not isinstance(client_secret, str):
        raise CondaAuthError("OAuth client secret must be text")

    redirect_uri = options.get(OAUTH_REDIRECT_URI_PARAM_NAME)
    if redirect_uri is not None and not isinstance(redirect_uri, str):
        raise CondaAuthError("OAuth redirect URI must be text")

    user_agent = options.get(OAUTH_USER_AGENT_PARAM_NAME)
    if user_agent is not None and not isinstance(user_agent, str):
        raise CondaAuthError("OAuth user agent must be text")

    output_stream_value = options.get("oauth_output_stream")
    if output_stream_value is not None and not hasattr(output_stream_value, "write"):
        raise CondaAuthError("OAuth output stream must be file-like")
    output_stream = cast(TextIO | None, output_stream_value)

    return OAuthLoginConfig(
        issuer_url=ensure_url_scheme(issuer_url),
        client_id=client_id,
        client_secret=client_secret,
        flow=flow,
        scopes=scopes,
        redirect_uri=redirect_uri,
        user_agent=user_agent,
        output_stream=output_stream,
    )
