"""
SafeShare Client

Main client class for interacting with SafeShare API.
"""

import re
import time
import uuid
import warnings
from pathlib import Path
from typing import BinaryIO, Optional, Union

import httpx

from safeshare.exceptions import (
    AuthenticationError,
    ChunkedUploadError,
    DownloadError,
    SafeShareError,
    UploadError,
    ValidationError,
    raise_for_status,
)
from safeshare.models import (
    ChunkedUploadSession,
    ChunkUploadResult,
    DownloadProgress,
    DownloadProgressCallback,
    FileInfo,
    ProgressCallback,
    PublicConfig,
    TokenCreatedResponse,
    TokenInfo,
    UploadProgress,
    UploadResult,
    UploadStatus,
    UserFilesResponse,
)


# Regex for validating claim codes (alphanumeric, dash, underscore)
CLAIM_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class SafeShareClient:
    """
    SafeShare API client.

    Provides methods for uploading, downloading, and managing files
    on a SafeShare server.

    Example:
        >>> client = SafeShareClient(
        ...     base_url="https://share.example.com",
        ...     api_token="safeshare_your_token_here"
        ... )
        >>> result = client.upload("document.pdf", expires_in_hours=48)
        >>> print(f"Download URL: {result.download_url}")
    """

    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        timeout: float = 300.0,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize SafeShare client.

        Args:
            base_url: Base URL of the SafeShare server (e.g., "https://share.example.com")
            api_token: API token for authentication (format: safeshare_<64 hex chars>)
            timeout: Request timeout in seconds (default: 300s for large uploads)
            verify_ssl: Whether to verify SSL certificates (default: True).
                        WARNING: Setting this to False is a security risk and should
                        only be used for local development with self-signed certificates.
        """
        self.base_url = base_url.rstrip("/")
        self._api_token = api_token  # Use private attribute for security
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Warn if SSL verification is disabled
        if not verify_ssl:
            warnings.warn(
                "SSL verification is disabled. This is insecure and should only "
                "be used for local development with self-signed certificates.",
                UserWarning,
                stacklevel=2,
            )

        # Server configuration (fetched on first use)
        self._config: Optional[PublicConfig] = None

        # Create HTTP client
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=self._build_headers(),
        )

    @property
    def api_token(self) -> Optional[str]:
        """API token (use with care - do not log this value)."""
        return self._api_token

    def __repr__(self) -> str:
        """String representation with redacted token."""
        token_display = "***" if self._api_token else "None"
        return (
            f"SafeShareClient(base_url={self.base_url!r}, "
            f"api_token={token_display}, timeout={self.timeout})"
        )

    def _build_headers(self) -> dict:
        """Build request headers with authentication."""
        headers = {
            "User-Agent": "SafeShare-Python-SDK/0.1.0",
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        return headers

    def _handle_response(self, response: httpx.Response) -> dict:
        """
        Handle API response and raise appropriate exceptions.

        Args:
            response: HTTP response object

        Returns:
            Parsed JSON response

        Raises:
            SafeShareError: On API errors
        """
        if response.status_code >= 400:
            try:
                error_data = response.json()
                message = error_data.get("error", "Unknown error")
                error_code = error_data.get("code")
            except Exception:
                message = response.text or f"HTTP {response.status_code}"
                error_code = None

            raise_for_status(response.status_code, message, error_code)

        if response.status_code == 204:
            return {}

        try:
            return response.json()
        except Exception:
            return {}

    def _validate_claim_code(self, claim_code: str) -> None:
        """Validate claim code format."""
        if not claim_code:
            raise ValidationError("Claim code cannot be empty")
        if not CLAIM_CODE_PATTERN.match(claim_code):
            raise ValidationError(
                f"Invalid claim code format. Must contain only alphanumeric characters, "
                f"dashes, and underscores."
            )

    def _validate_upload_id(self, upload_id: str) -> None:
        """Validate upload ID format (UUID)."""
        try:
            uuid.UUID(upload_id)
        except ValueError:
            raise ValidationError(f"Invalid upload ID format. Must be a valid UUID.")

    def _validate_filename(self, filename: str) -> None:
        """Validate filename for dangerous characters."""
        if not filename:
            raise ValidationError("Filename cannot be empty")
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValidationError(
                "Invalid filename. Must not contain path separators or '..'."
            )

    def close(self) -> None:
        """Close the HTTP client connection."""
        self._client.close()

    def __enter__(self) -> "SafeShareClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ==================== Configuration ====================

    def get_config(self) -> PublicConfig:
        """
        Get server configuration.

        Returns:
            Server configuration including limits and capabilities.
        """
        response = self._client.get("/api/config")
        data = self._handle_response(response)
        self._config = PublicConfig(**data)
        return self._config

    @property
    def config(self) -> PublicConfig:
        """Get cached server configuration (fetches if not cached)."""
        if self._config is None:
            self.get_config()
        return self._config  # type: ignore

    # ==================== File Upload ====================

    def upload(
        self,
        file: Union[str, Path, BinaryIO],
        filename: Optional[str] = None,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """
        Upload a file to SafeShare.

        Automatically uses chunked upload for large files (above server threshold).

        Args:
            file: File path or file-like object to upload
            filename: Override filename (uses original if not provided)
            expires_in_hours: Hours until file expires (uses server default if not provided)
            max_downloads: Maximum download count (unlimited if not provided)
            password: Password to protect the file
            progress_callback: Callback function for upload progress

        Returns:
            UploadResult with claim code and download URL

        Raises:
            UploadError: On upload failure
            FileTooLargeError: If file exceeds maximum size
            QuotaExceededError: If storage quota is exceeded
        """
        # Handle file path vs file object
        if isinstance(file, (str, Path)):
            file_path = Path(file)
            if not file_path.exists():
                raise UploadError(f"File not found: {file_path}")
            file_size = file_path.stat().st_size
            if filename is None:
                filename = file_path.name
            file_obj: BinaryIO = open(file_path, "rb")  # type: ignore
            should_close = True
        else:
            file_obj = file
            should_close = False
            # Try to get file size
            current_pos = file_obj.tell()
            file_obj.seek(0, 2)  # Seek to end
            file_size = file_obj.tell()
            file_obj.seek(current_pos)  # Restore position
            if filename is None:
                filename = getattr(file_obj, "name", "upload")
                if isinstance(filename, (str, Path)):
                    filename = Path(filename).name

        # Validate filename
        self._validate_filename(filename)

        try:
            # Check if chunked upload is needed
            config = self.config
            if config.chunked_upload_enabled and file_size >= config.chunked_upload_threshold:
                return self._chunked_upload(
                    file_obj,
                    filename,
                    file_size,
                    expires_in_hours=expires_in_hours,
                    max_downloads=max_downloads,
                    password=password,
                    progress_callback=progress_callback,
                )
            else:
                return self._simple_upload(
                    file_obj,
                    filename,
                    file_size,
                    expires_in_hours=expires_in_hours,
                    max_downloads=max_downloads,
                    password=password,
                    progress_callback=progress_callback,
                )
        finally:
            if should_close:
                file_obj.close()

    def _simple_upload(
        self,
        file_obj: BinaryIO,
        filename: str,
        file_size: int,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Perform simple (non-chunked) upload."""
        # Build form data
        files = {"file": (filename, file_obj)}
        data = {}
        if expires_in_hours is not None:
            data["expires_in_hours"] = str(expires_in_hours)
        if max_downloads is not None:
            data["max_downloads"] = str(max_downloads)
        if password is not None:
            data["password"] = password

        # Report initial progress
        if progress_callback:
            progress_callback(UploadProgress.from_bytes(0, file_size))

        try:
            response = self._client.post("/api/upload", files=files, data=data)
            result_data = self._handle_response(response)

            # Report completion
            if progress_callback:
                progress_callback(UploadProgress.from_bytes(file_size, file_size))

            return UploadResult(**result_data)
        except SafeShareError:
            raise
        except Exception as e:
            raise UploadError(f"Upload failed: {e}") from e

    def _chunked_upload(
        self,
        file_obj: BinaryIO,
        filename: str,
        file_size: int,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> UploadResult:
        """Perform chunked upload for large files."""
        # Initialize upload session
        session = self.init_chunked_upload(
            filename=filename,
            total_size=file_size,
            expires_in_hours=expires_in_hours,
            max_downloads=max_downloads,
            password=password,
        )

        chunk_size = session.chunk_size
        total_chunks = session.total_chunks
        bytes_uploaded = 0

        try:
            # Upload each chunk
            for chunk_number in range(total_chunks):
                chunk_data = file_obj.read(chunk_size)
                if not chunk_data:
                    break

                self.upload_chunk(session.upload_id, chunk_number, chunk_data)
                bytes_uploaded += len(chunk_data)

                # Report progress
                if progress_callback:
                    progress_callback(
                        UploadProgress.from_bytes(
                            bytes_uploaded,
                            file_size,
                            chunks_completed=chunk_number + 1,
                            total_chunks=total_chunks,
                        )
                    )

            # Complete the upload
            return self.complete_chunked_upload(session.upload_id)

        except Exception as e:
            raise ChunkedUploadError(f"Chunked upload failed: {e}") from e

    def init_chunked_upload(
        self,
        filename: str,
        total_size: int,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
    ) -> ChunkedUploadSession:
        """
        Initialize a chunked upload session.

        Args:
            filename: Original filename
            total_size: Total file size in bytes
            expires_in_hours: Hours until file expires
            max_downloads: Maximum download count
            password: Password to protect the file

        Returns:
            ChunkedUploadSession with upload_id and chunk info
        """
        # Validate filename
        self._validate_filename(filename)

        data: dict = {
            "filename": filename,
            "total_size": total_size,
        }
        if expires_in_hours is not None:
            data["expires_in_hours"] = expires_in_hours
        if max_downloads is not None:
            data["max_downloads"] = max_downloads
        if password is not None:
            data["password"] = password

        response = self._client.post("/api/upload/init", json=data)
        result = self._handle_response(response)
        return ChunkedUploadSession(**result)

    def upload_chunk(
        self,
        upload_id: str,
        chunk_number: int,
        chunk_data: bytes,
    ) -> ChunkUploadResult:
        """
        Upload a single chunk.

        Args:
            upload_id: Upload session ID
            chunk_number: Zero-based chunk index
            chunk_data: Chunk binary data

        Returns:
            ChunkUploadResult with progress info
        """
        # Validate upload_id
        self._validate_upload_id(upload_id)

        files = {"chunk": ("chunk", chunk_data)}
        response = self._client.post(
            f"/api/upload/chunk/{upload_id}/{chunk_number}",
            files=files,
        )
        result = self._handle_response(response)
        return ChunkUploadResult(**result)

    def complete_chunked_upload(self, upload_id: str) -> UploadResult:
        """
        Complete a chunked upload.

        Args:
            upload_id: Upload session ID

        Returns:
            UploadResult with claim code and download URL
        """
        # Validate upload_id
        self._validate_upload_id(upload_id)

        response = self._client.post(f"/api/upload/complete/{upload_id}")
        result = self._handle_response(response)

        # Handle async processing (202 Accepted)
        if response.status_code == 202:
            return self._wait_for_completion(upload_id)

        return UploadResult(**result)

    def get_upload_status(self, upload_id: str) -> UploadStatus:
        """
        Get status of a chunked upload.

        Args:
            upload_id: Upload session ID

        Returns:
            UploadStatus with progress info
        """
        # Validate upload_id
        self._validate_upload_id(upload_id)

        response = self._client.get(f"/api/upload/status/{upload_id}")
        result = self._handle_response(response)
        return UploadStatus(**result)

    def _wait_for_completion(
        self,
        upload_id: str,
        poll_interval: float = 2.0,
        max_wait: float = 600.0,
    ) -> UploadResult:
        """Wait for async upload completion."""
        start_time = time.time()
        while time.time() - start_time < max_wait:
            status = self.get_upload_status(upload_id)

            if status.status == "completed" and status.claim_code:
                return UploadResult(
                    claim_code=status.claim_code,
                    download_url=status.download_url or "",
                    file_size=0,  # Not available in status
                    original_filename=status.filename,
                )
            elif status.status == "failed":
                raise ChunkedUploadError(status.error_message or "Upload failed")

            time.sleep(poll_interval)

        raise ChunkedUploadError("Upload timed out waiting for completion")

    # ==================== File Download ====================

    def download(
        self,
        claim_code: str,
        destination: Union[str, Path, BinaryIO],
        password: Optional[str] = None,
        progress_callback: Optional[DownloadProgressCallback] = None,
    ) -> Path:
        """
        Download a file by claim code.

        Args:
            claim_code: File claim code
            destination: Destination file path or file-like object
            password: Password if file is protected
            progress_callback: Callback function for download progress

        Returns:
            Path to downloaded file

        Raises:
            DownloadError: On download failure
            NotFoundError: If file not found or expired
            PasswordRequiredError: If password is required but not provided
        """
        # Validate claim code
        self._validate_claim_code(claim_code)

        # Build URL - password sent via query parameter as the server API expects
        # Note: This is the server's design; passwords are transmitted over HTTPS
        url = f"/api/claim/{claim_code}"
        params = {}
        if password:
            params["password"] = password

        try:
            # Use streaming download
            with self._client.stream("GET", url, params=params) as response:
                if response.status_code >= 400:
                    # Read error body
                    response.read()
                    try:
                        error_data = response.json()
                        message = error_data.get("error", "Download failed")
                        error_code = error_data.get("code")
                    except Exception:
                        message = f"HTTP {response.status_code}"
                        error_code = None
                    raise_for_status(response.status_code, message, error_code)

                # Get total size from headers
                total_size = response.headers.get("content-length")
                total_size = int(total_size) if total_size else None

                # Handle destination - resolve to absolute path for safety
                if isinstance(destination, (str, Path)):
                    dest_path = Path(destination).resolve()
                    # Ensure parent directory exists
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    file_obj: BinaryIO = open(dest_path, "wb")  # type: ignore
                    should_close = True
                else:
                    file_obj = destination
                    dest_path = Path(getattr(file_obj, "name", "download"))
                    should_close = False

                try:
                    bytes_downloaded = 0
                    start_time = time.time()

                    for chunk in response.iter_bytes(chunk_size=65536):
                        file_obj.write(chunk)
                        bytes_downloaded += len(chunk)

                        if progress_callback:
                            elapsed = time.time() - start_time
                            speed = bytes_downloaded / elapsed if elapsed > 0 else None
                            progress_callback(
                                DownloadProgress.from_bytes(
                                    bytes_downloaded,
                                    total_size,
                                    speed,
                                )
                            )
                finally:
                    if should_close:
                        file_obj.close()

                return dest_path

        except SafeShareError:
            raise
        except Exception as e:
            raise DownloadError(f"Download failed: {e}") from e

    def get_file_info(self, claim_code: str, password: Optional[str] = None) -> FileInfo:
        """
        Get file metadata without downloading.

        Args:
            claim_code: File claim code
            password: Password if file is protected

        Returns:
            FileInfo with file metadata
        """
        # Validate claim code
        self._validate_claim_code(claim_code)

        url = f"/api/claim/{claim_code}/info"
        params = {}
        if password:
            params["password"] = password

        response = self._client.get(url, params=params)
        result = self._handle_response(response)
        return FileInfo(**result)

    # ==================== File Management ====================

    def list_files(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> UserFilesResponse:
        """
        List current user's files.

        Args:
            limit: Number of results per page (max 100)
            offset: Pagination offset

        Returns:
            UserFilesResponse with files list and pagination info
        """
        if not self._api_token:
            raise AuthenticationError("API token required for file management")

        response = self._client.get(
            "/api/user/files",
            params={"limit": limit, "offset": offset},
        )
        result = self._handle_response(response)
        return UserFilesResponse(**result)

    def delete_file(self, file_id: int) -> None:
        """
        Delete a file by ID.

        Args:
            file_id: File ID to delete
        """
        if not self._api_token:
            raise AuthenticationError("API token required for file management")

        response = self._client.delete(
            "/api/user/files/delete",
            json={"file_id": file_id},
        )
        self._handle_response(response)

    def rename_file(self, file_id: int, new_filename: str) -> None:
        """
        Rename a file.

        Args:
            file_id: File ID to rename
            new_filename: New filename
        """
        if not self._api_token:
            raise AuthenticationError("API token required for file management")

        # Validate filename
        self._validate_filename(new_filename)

        response = self._client.post(
            "/api/user/files/rename",
            json={"file_id": file_id, "new_filename": new_filename},
        )
        self._handle_response(response)

    def update_expiration(self, file_id: int, expires_in_hours: float) -> None:
        """
        Update file expiration time.

        Args:
            file_id: File ID to update
            expires_in_hours: New expiration in hours from now
        """
        if not self._api_token:
            raise AuthenticationError("API token required for file management")

        response = self._client.post(
            "/api/user/files/update-expiration",
            json={"file_id": file_id, "expires_in_hours": expires_in_hours},
        )
        self._handle_response(response)

    def regenerate_claim_code(self, file_id: int) -> str:
        """
        Generate a new claim code for a file.

        The old claim code becomes invalid immediately.

        Args:
            file_id: File ID to regenerate code for

        Returns:
            New claim code
        """
        if not self._api_token:
            raise AuthenticationError("API token required for file management")

        response = self._client.post(
            "/api/user/files/regenerate-claim-code",
            json={"file_id": file_id},
        )
        result = self._handle_response(response)
        return result["claim_code"]

    # ==================== API Token Management ====================

    def create_token(
        self,
        name: str,
        scopes: list,
        expires_in_days: Optional[int] = None,
    ) -> TokenCreatedResponse:
        """
        Create a new API token.

        Note: This requires session authentication, not token auth.

        Args:
            name: Human-readable token name
            scopes: Permission scopes (upload, download, manage, admin)
            expires_in_days: Days until expiration (max 365, None for no expiration)

        Returns:
            TokenCreatedResponse with full token value
        """
        data: dict = {
            "name": name,
            "scopes": scopes,
        }
        if expires_in_days is not None:
            data["expires_in_days"] = expires_in_days

        response = self._client.post("/api/tokens", json=data)
        result = self._handle_response(response)
        return TokenCreatedResponse(**result)

    def list_tokens(self) -> list:
        """
        List current user's API tokens.

        Returns:
            List of TokenInfo objects
        """
        response = self._client.get("/api/tokens")
        result = self._handle_response(response)
        return [TokenInfo(**t) for t in result.get("tokens", [])]

    def revoke_token(self, token_id: int) -> None:
        """
        Revoke an API token.

        Note: This requires session authentication, not token auth.

        Args:
            token_id: Token ID to revoke
        """
        response = self._client.delete(f"/api/tokens/{token_id}")
        self._handle_response(response)
