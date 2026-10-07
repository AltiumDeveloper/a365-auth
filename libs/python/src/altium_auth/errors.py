"""Exception types raised by altium_auth."""

from __future__ import annotations


def _truncate(text: str, limit: int = 500) -> str:
    """Truncate a string for error messages (mirrors the reference 500-char cap)."""
    return text[:limit]


class AltiumAuthError(Exception):
    """Base class for all errors raised by altium_auth."""


class ConfigurationError(AltiumAuthError, ValueError):
    """Invalid config: a missing required field or a malformed endpoint URL."""


class OAuthError(AltiumAuthError):
    """A token/revocation/scope endpoint returned a non-success response."""

    def __init__(
        self,
        message: str,
        *,
        status: int,
        error: str = "",
        error_description: str = "",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error = error
        self.error_description = error_description


class ActionWaitError(AltiumAuthError):
    """The ActionWait long-poll failed, timed out, or was cancelled."""


class StateMismatchError(ActionWaitError):
    """The state returned by ActionWait did not match the wait token (CSRF guard)."""


class TransportError(AltiumAuthError):
    """A network-level failure talking to an endpoint."""


class TlsError(TransportError):
    """A TLS/certificate failure: a configuration error, never retried."""
