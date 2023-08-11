from .base import AuthManager  # noqa: F401
from ..constants import OAUTH2_NAME, HTTP_BASIC_AUTH_NAME
from .oauth2 import OAuth2Manager, OAuth2Handler  # noqa: F401
from .basic_auth import BasicAuthManager, BasicAuthHandler  # noqa: F401

auth_manager_mapping = {
    OAUTH2_NAME: OAuth2Manager,
    HTTP_BASIC_AUTH_NAME: BasicAuthManager,
}
