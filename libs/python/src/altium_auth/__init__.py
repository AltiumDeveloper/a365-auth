"""altium_auth — Altium 365 OAuth2/OIDC authentication (PKCE + ActionWait). Zero runtime deps."""

from __future__ import annotations

from .client import AltiumAuthClient
from .config import AltiumAuthConfig
from .endpoints import (
    COMMERCIAL_CLOUD_ENDPOINTS,
    GOV_CLOUD_ENDPOINTS,
    AltiumEndpoints,
    aes_endpoints,
)
from .errors import (
    ActionWaitError,
    AltiumAuthError,
    ConfigurationError,
    OAuthError,
    StateMismatchError,
    TlsError,
    TransportError,
)
from .models import AuthorizationRequest, TokenSet, WorkspaceSelection

__version__ = "0.2.0"

__all__ = [
    "AltiumAuthClient",
    "AltiumAuthConfig",
    "AltiumEndpoints",
    "TokenSet",
    "AuthorizationRequest",
    "WorkspaceSelection",
    "COMMERCIAL_CLOUD_ENDPOINTS",
    "GOV_CLOUD_ENDPOINTS",
    "aes_endpoints",
    "AltiumAuthError",
    "ConfigurationError",
    "OAuthError",
    "ActionWaitError",
    "StateMismatchError",
    "TlsError",
    "TransportError",
    "__version__",
]
