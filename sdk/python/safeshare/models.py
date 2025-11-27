"""
SafeShare SDK Data Models

Pydantic models for SafeShare API requests and responses.
"""

from datetime import datetime
from typing import Callable, List, Optional

from pydantic import BaseModel, Field


class UploadResult(BaseModel):
    """Result of a successful file upload."""

    claim_code: str = Field(description="Unique code to retrieve the file")
    download_url: str = Field(description="Full URL for downloading the file")
    expires_at: Optional[datetime] = Field(default=None, description="Expiration timestamp")
    max_downloads: Optional[int] = Field(default=None, description="Maximum download count")
    file_size: int = Field(description="File size in bytes")
    original_filename: str = Field(description="Original filename")
    sha256_hash: Optional[str] = Field(default=None, description="SHA-256 hash of the file")


class FileInfo(BaseModel):
    """File metadata information."""

    claim_code: str
    original_filename: str
    file_size: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    download_count: int = 0
    max_downloads: Optional[int] = None
    downloads_remaining: Optional[int] = None
    password_protected: bool = False
    sha256_hash: Optional[str] = None


class UserFile(BaseModel):
    """File in user's file list."""

    id: int
    claim_code: str
    original_filename: str
    file_size: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    download_count: int = 0
    completed_downloads: int = 0
    max_downloads: Optional[int] = None
    password_protected: bool = False
    sha256_hash: Optional[str] = None


class UserFilesResponse(BaseModel):
    """Response for listing user's files."""

    files: List[UserFile]
    total: int
    limit: int
    offset: int


class ChunkedUploadSession(BaseModel):
    """Chunked upload session information."""

    upload_id: str = Field(description="Upload session UUID")
    chunk_size: int = Field(description="Size of each chunk in bytes")
    total_chunks: int = Field(description="Total number of chunks expected")
    expires_at: datetime = Field(description="Session expiration timestamp")


class ChunkUploadResult(BaseModel):
    """Result of uploading a single chunk."""

    upload_id: str
    chunk_number: int
    chunks_received: int
    total_chunks: int
    complete: bool


class UploadStatus(BaseModel):
    """Status of a chunked upload."""

    upload_id: str
    filename: str
    status: str  # uploading, processing, completed, failed
    chunks_received: int
    total_chunks: int
    missing_chunks: List[int] = Field(default_factory=list)
    complete: bool
    claim_code: Optional[str] = None
    download_url: Optional[str] = None
    error_message: Optional[str] = None
    expires_at: datetime


class UploadProgress(BaseModel):
    """Progress information for upload callbacks."""

    bytes_uploaded: int = Field(description="Total bytes uploaded so far")
    total_bytes: int = Field(description="Total file size in bytes")
    chunks_completed: int = Field(default=0, description="Number of chunks completed")
    total_chunks: int = Field(default=1, description="Total number of chunks")
    percentage: float = Field(description="Upload progress percentage (0-100)")
    speed_bps: Optional[float] = Field(default=None, description="Upload speed in bytes/second")

    @classmethod
    def from_bytes(
        cls,
        bytes_uploaded: int,
        total_bytes: int,
        chunks_completed: int = 0,
        total_chunks: int = 1,
        speed_bps: Optional[float] = None,
    ) -> "UploadProgress":
        """Create progress from byte counts."""
        percentage = (bytes_uploaded / total_bytes * 100) if total_bytes > 0 else 0
        return cls(
            bytes_uploaded=bytes_uploaded,
            total_bytes=total_bytes,
            chunks_completed=chunks_completed,
            total_chunks=total_chunks,
            percentage=round(percentage, 2),
            speed_bps=speed_bps,
        )


class DownloadProgress(BaseModel):
    """Progress information for download callbacks."""

    bytes_downloaded: int = Field(description="Total bytes downloaded so far")
    total_bytes: Optional[int] = Field(default=None, description="Total file size (if known)")
    percentage: Optional[float] = Field(
        default=None, description="Download progress percentage (0-100)"
    )
    speed_bps: Optional[float] = Field(default=None, description="Download speed in bytes/second")

    @classmethod
    def from_bytes(
        cls,
        bytes_downloaded: int,
        total_bytes: Optional[int] = None,
        speed_bps: Optional[float] = None,
    ) -> "DownloadProgress":
        """Create progress from byte counts."""
        percentage = None
        if total_bytes and total_bytes > 0:
            percentage = round(bytes_downloaded / total_bytes * 100, 2)
        return cls(
            bytes_downloaded=bytes_downloaded,
            total_bytes=total_bytes,
            percentage=percentage,
            speed_bps=speed_bps,
        )


class PublicConfig(BaseModel):
    """Public server configuration."""

    version: str
    max_file_size: int
    default_expiration_hours: int
    max_expiration_hours: int
    chunked_upload_enabled: bool
    chunked_upload_threshold: int
    chunk_size: int
    require_auth_for_upload: bool


class TokenInfo(BaseModel):
    """API token information."""

    id: int
    name: str
    token_prefix: str
    scopes: List[str]
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


class TokenCreatedResponse(BaseModel):
    """Response when creating a new API token."""

    id: int
    name: str
    token: str = Field(description="Full token value - only shown once")
    scopes: List[str]
    expires_at: Optional[datetime] = None
    created_at: datetime


# Type alias for progress callbacks
ProgressCallback = Callable[[UploadProgress], None]
DownloadProgressCallback = Callable[[DownloadProgress], None]
