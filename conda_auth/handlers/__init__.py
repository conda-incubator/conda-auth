from conda.base.context import context

from .base import AuthManager  # noqa: F401
from .oauth2 import OAuth2Manager, OAuth2Handler  # noqa: F401
from .basic_auth import BasicAuthManager, BasicAuthHandler  # noqa: F401

oauth2 = OAuth2Manager(context)
basic_auth = BasicAuthManager(context)

OAuth2Handler.set_cache(oauth2.cache)
BasicAuthHandler.set_cache(basic_auth.cache)
