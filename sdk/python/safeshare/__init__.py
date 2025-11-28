"""
SafeShare Python SDK

A Python client library for the SafeShare file sharing service.

Example usage:
    from safeshare import SafeShareClient

    # Initialize with API token
    client = SafeShareClient(
        base_url="https://share.example.com",
        api_token="safeshare_your_token_here"
    )

    # Upload a file
    result = client.upload("document.pdf", expires_in_hours=48)
    print(f"Download URL: {result.download_url}")

    # Download a file
    client.download("claim_code_here", "downloaded_file.pdf")
"""

from safeshare.client import SafeShareClient
from safeshare.exceptions import (
    SafeShareError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    UploadError,
    DownloadError,
    ValidationError,
)
from safeshare.models import (
    UploadResult,
    FileInfo,
    UserFile,
    ChunkedUploadSession,
    UploadProgress,
)

__version__ = "0.1.0"
__all__ = [
    "SafeShareClient",
    "SafeShareError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "UploadError",
    "DownloadError",
    "ValidationError",
    "UploadResult",
    "FileInfo",
    "UserFile",
    "ChunkedUploadSession",
    "UploadProgress",
]
