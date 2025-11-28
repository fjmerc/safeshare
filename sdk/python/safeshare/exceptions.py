"""
SafeShare SDK Exceptions

Custom exception classes for handling SafeShare API errors.
"""

from typing import Optional


class SafeShareError(Exception):
    """Base exception for SafeShare SDK errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code

    def __str__(self) -> str:
        parts = [self.message]
        if self.status_code:
            parts.append(f"(HTTP {self.status_code})")
        if self.error_code:
            parts.append(f"[{self.error_code}]")
        return " ".join(parts)


class AuthenticationError(SafeShareError):
    """Raised when authentication fails."""

    pass


class NotFoundError(SafeShareError):
    """Raised when a resource is not found."""

    pass


class RateLimitError(SafeShareError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        status_code: int = 429,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(message, status_code)
        self.retry_after = retry_after


class UploadError(SafeShareError):
    """Raised when file upload fails."""

    pass


class DownloadError(SafeShareError):
    """Raised when file download fails."""

    pass


class ValidationError(SafeShareError):
    """Raised when request validation fails."""

    pass


class QuotaExceededError(SafeShareError):
    """Raised when storage quota is exceeded."""

    pass


class FileTooLargeError(SafeShareError):
    """Raised when file exceeds maximum size limit."""

    pass


class PasswordRequiredError(SafeShareError):
    """Raised when a password is required to access a file."""

    pass


class DownloadLimitReachedError(SafeShareError):
    """Raised when download limit for a file has been reached."""

    pass


class ChunkedUploadError(SafeShareError):
    """Raised when chunked upload operations fail."""

    pass


def raise_for_status(status_code: int, message: str, error_code: Optional[str] = None) -> None:
    """
    Raise appropriate exception based on HTTP status code.

    Args:
        status_code: HTTP status code
        message: Error message from response
        error_code: Optional error code from response

    Raises:
        Appropriate SafeShareError subclass
    """
    if status_code == 401:
        if error_code == "password_required":
            raise PasswordRequiredError(message, status_code, error_code)
        raise AuthenticationError(message, status_code, error_code)
    elif status_code == 403:
        raise AuthenticationError(message, status_code, error_code)
    elif status_code == 404:
        raise NotFoundError(message, status_code, error_code)
    elif status_code == 410:
        if error_code == "download_limit_reached":
            raise DownloadLimitReachedError(message, status_code, error_code)
        raise NotFoundError(message, status_code, error_code)
    elif status_code == 413:
        raise FileTooLargeError(message, status_code, error_code)
    elif status_code == 429:
        raise RateLimitError(message, status_code)
    elif status_code == 507:
        raise QuotaExceededError(message, status_code, error_code)
    elif status_code >= 400:
        raise SafeShareError(message, status_code, error_code)
