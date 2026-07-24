"""
A place for all of our constant variables
"""

PLUGIN_NAME = "conda-auth"

AUTH_ALLOW_PLAINTEXT_HTTP_PARAM = "auth_allow_plaintext_http"

SUCCESSFUL_LOGIN_MESSAGE = "Successfully stored credentials"

SUCCESSFUL_LOGOUT_MESSAGE = "Successfully removed credentials"

PROXY_AUTH_NAME = "proxy-basic"

PROXY_NETWORK_COMMANDS = frozenset(
    (
        "create",
        "env",
        "install",
        "remove",
        "repoquery",
        "search",
        "update",
    )
)

PROXY_COMMAND_NAME = "proxy"
