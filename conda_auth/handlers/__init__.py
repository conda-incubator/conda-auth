from .base import AuthManager
from .oauth2 import OAuth2Manager, OAuth2Handler  # noqa: F401
from .basic_auth import BasicAuthManager, BasicAuthHandler  # noqa: F401


def get_auth_manager(manager: str) -> AuthManager:
    """Helper function used to instantiate our ``AuthManager`` objects"""
    from conda.base.context import context

    context.__init__()

    if manager == "oauth2":
        return OAuth2Manager(context)
    elif manager == "basic_auth":
        return BasicAuthManager(context)
    else:
        raise NotImplementedError(f"Unable to find requested auth manager: {manager}")
