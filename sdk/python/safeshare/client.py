"""
SafeShare Client

Main client class for interacting with SafeShare API.
"""

import io
import os
import re
import tempfile
import time
import uuid
import warnings
from pathlib import Path
from typing import BinaryIO, Optional, Union

import httpx

from safeshare import e2e
from safeshare.e2e import DecryptedFile
from safeshare.exceptions import (
    AuthenticationError,
    ClientEncryptionRequiredError,
    MetadataNotRemovedError,
    PayloadTooLargeError,
    ChunkedUploadError,
    DownloadError,
    RateLimitError,
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



# Bounds on the wait after a rate-limited status poll, in seconds (the same
# range the web uploader uses).
RATE_LIMIT_POLL_MIN_WAIT = 15.0
RATE_LIMIT_POLL_MAX_WAIT = 60.0


def _write_private(path: Path, data: bytes, overwrite: bool) -> None:
    """Write data with mode 0600. Without overwrite the file must not exist
    (O_EXCL also refuses a symlink); with it, a temp file is renamed over the
    destination so a symlink there is replaced, not followed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise DownloadError(f"Destination already exists: {path}") from None
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".safeshare-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _rate_limit_poll_delay(error: RateLimitError) -> float:
    """Seconds to wait after a 429 from the status endpoint (T52)."""
    wait = max(RATE_LIMIT_POLL_MIN_WAIT, float(error.retry_after or 0))
    return min(wait, RATE_LIMIT_POLL_MAX_WAIT)

_ENCRYPT_MODES = ("auto", "always", "never")


def _env_any(*names: str) -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return ""


def _normalize_proxy(url: str, source: str = "proxy") -> str:
    url = url.strip()
    scheme, sep, rest = url.partition("://")
    if not sep or scheme.lower() not in ("socks5", "socks5h", "http", "https") or not rest:
        raise ValidationError(f"{source} must be a URL such as socks5://127.0.0.1:9050")
    return url


def _no_proxy_patterns(no_proxy: str) -> list:
    """httpx mount patterns for NO_PROXY entries (as httpx itself builds them)."""
    import ipaddress

    out = []
    for host in (h.strip() for h in no_proxy.split(",")):
        if not host:
            continue
        if "://" in host:
            out.append(host)
            continue
        try:
            ip = ipaddress.ip_address(host)
            out.append(f"all://{host}" if ip.version == 4 else f"all://[{host}]")
            continue
        except ValueError:
            pass
        out.append("all://localhost" if host.lower() == "localhost" else f"all://*{host}")
    return out


def _proxy_options(proxy: Optional[str], disable_proxy: bool, verify: bool = True) -> dict:
    """httpx options for the proxy rules in SafeShareClient.__init__."""
    if proxy:
        return {"proxy": _normalize_proxy(proxy), "trust_env": False}
    if disable_proxy:
        return {"trust_env": False}
    https_p = _env_any("HTTPS_PROXY", "https_proxy")
    http_p = _env_any("HTTP_PROXY", "http_proxy")
    if https_p and http_p:
        return {}  # httpx's usual per-scheme and NO_PROXY rules
    single = https_p or http_p or _env_any("ALL_PROXY", "all_proxy")
    if not single:
        return {}
    single = _normalize_proxy(single, "The proxy environment variable")
    no_proxy = _env_any("NO_PROXY", "no_proxy")
    if not no_proxy:
        return {"proxy": single}
    if no_proxy.strip() == "*":
        return {"trust_env": False}  # NO_PROXY=* means no proxy at all
    # The one proxy covers both schemes; only hosts NO_PROXY names go direct.
    mounts: dict = {"all://": httpx.HTTPTransport(proxy=single, verify=verify)}
    for pattern in _no_proxy_patterns(no_proxy):
        mounts[pattern] = None
    return {"mounts": mounts, "trust_env": False}


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
        proxy: Optional[str] = None,
        disable_proxy: bool = False,
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
            proxy: Send every request through this proxy, e.g.
                   "socks5://127.0.0.1:9050" for Tor (host names are resolved
                   by the proxy). By default ALL_PROXY/HTTPS_PROXY/HTTP_PROXY
                   are honoured; when only one of them is set it covers every
                   request, so an http:// URL can't bypass it.
            disable_proxy: Ignore the proxy environment variables.
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

        # Create HTTP client. Redirects are not followed (httpx default), so
        # the token, file passwords and requests never go to another origin.
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=self._build_headers(),
            **_proxy_options(proxy, disable_proxy, verify_ssl),
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

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "")
                raise RateLimitError(
                    message,
                    429,
                    retry_after=int(retry_after) if retry_after.isdigit() else None,
                )
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
        encrypt: str = "auto",
        show_filename: bool = False,
        keep_metadata: bool = False,
    ) -> UploadResult:
        """
        Upload a file to SafeShare.

        Automatically uses chunked upload for large files (above server threshold).

        End-to-end encryption (``encrypt``): "auto" (default) encrypts on
        servers in Ghost (anonymous) mode or that require client-side
        encryption; "always" encrypts on any server (use it if the server
        itself isn't trusted to report its mode); "never" never does. The file
        is encrypted on this machine in the web app's format and padded to a
        size bucket, its name is hidden unless ``show_filename``, and the
        result's ``share_url`` carries the key. The file is held in memory.
        The SDK can't remove metadata: on Ghost servers JPEG, PNG, PDF and
        Office files raise MetadataNotRemovedError unless ``keep_metadata``.

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
            file_size = file_obj.tell() - current_pos  # what is left to read
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
            if self.will_encrypt(encrypt):
                return self._upload_encrypted(
                    file_obj,
                    filename,
                    file_size,
                    config,
                    expires_in_hours=expires_in_hours,
                    max_downloads=max_downloads,
                    password=password,
                    progress_callback=progress_callback,
                    show_filename=show_filename,
                    keep_metadata=keep_metadata,
                )
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

    def will_encrypt(self, encrypt: str = "auto") -> bool:
        """Whether upload() with this ``encrypt`` mode encrypts on this server.

        Raises ClientEncryptionRequiredError for "never" on a server that
        requires encryption.
        """
        if encrypt not in _ENCRYPT_MODES:
            raise ValidationError(f"encrypt must be one of {', '.join(_ENCRYPT_MODES)}")
        config = self.config
        if encrypt == "always":
            return True
        if encrypt == "never":
            if config.client_encryption_required:
                raise ClientEncryptionRequiredError("This server only accepts files encrypted before upload")
            return False
        return config.anonymous_mode or config.client_encryption_required

    def _upload_encrypted(
        self,
        file_obj: BinaryIO,
        filename: str,
        file_size: int,
        config: PublicConfig,
        expires_in_hours: Optional[float],
        max_downloads: Optional[int],
        password: Optional[str],
        progress_callback: Optional[ProgressCallback],
        show_filename: bool,
        keep_metadata: bool,
    ) -> UploadResult:
        """Encrypt in memory in the web app's format, then upload the ciphertext."""
        if file_size > e2e.MAX_ENCRYPTED_PAYLOAD:
            raise PayloadTooLargeError(
                f"Encrypting holds the whole file in memory, and the limit is {e2e.MAX_ENCRYPTED_PAYLOAD} bytes"
            )
        parts = []
        remaining = file_size + 1
        while remaining > 0:
            chunk = file_obj.read(min(remaining, 1 << 24))
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                raise UploadError("The file must be opened in binary mode")
            parts.append(chunk)
            remaining -= len(chunk)
        data = b"".join(parts)
        del parts
        if len(data) != file_size:
            raise UploadError("The file changed while it was being read")

        kind = e2e.metadata_file_type(data)
        if kind and config.anonymous_mode and config.strip_metadata and not keep_metadata:
            raise MetadataNotRemovedError(
                f"This {kind} may contain metadata (author, location, dates) and the server cannot remove it "
                "from an encrypted file; scrub it first, for example with mat2, or pass keep_metadata=True"
            )

        # Always padded (SF02), whatever the server says about its mode.
        payload = e2e.wrap_payload("" if show_filename else filename, data, True, config.max_file_size)
        del data
        key_str = e2e.generate_key()
        blob = e2e.encrypt_blob(e2e.decode_key(key_str), payload)
        del payload

        upload_name = filename if show_filename else e2e.ENCRYPTED_FILENAME
        src = io.BytesIO(blob)
        upload = (
            self._chunked_upload
            if config.chunked_upload_enabled and len(blob) >= config.chunked_upload_threshold
            else self._simple_upload
        )
        result = upload(
            src,
            upload_name,
            len(blob),
            expires_in_hours=expires_in_hours,
            max_downloads=max_downloads,
            password=password,
            progress_callback=progress_callback,
            client_encrypted=True,
        )
        result.encrypted = True
        result.original_filename = filename
        if not result.file_size:  # async chunked completion doesn't report it
            result.file_size = len(blob)
        result.encryption_key = key_str
        result.share_url = e2e.build_share_url(self.base_url, result.claim_code, key_str)
        if kind and config.strip_metadata:
            result.metadata_kept = kind
        return result

    def _simple_upload(
        self,
        file_obj: BinaryIO,
        filename: str,
        file_size: int,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
        client_encrypted: bool = False,
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
        headers = {}
        if client_encrypted:
            data["client_encrypted"] = "true"
            headers["X-SafeShare-Client-Encrypted"] = "true"

        # Report initial progress
        if progress_callback:
            progress_callback(UploadProgress.from_bytes(0, file_size))

        try:
            response = self._client.post("/api/upload", files=files, data=data, headers=headers)
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
        client_encrypted: bool = False,
    ) -> UploadResult:
        """Perform chunked upload for large files."""
        # Initialize upload session
        session = self.init_chunked_upload(
            filename=filename,
            total_size=file_size,
            expires_in_hours=expires_in_hours,
            max_downloads=max_downloads,
            password=password,
            client_encrypted=client_encrypted,
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
        client_encrypted: bool = False,
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
        headers = {}
        if client_encrypted:
            data["client_encrypted"] = True
            headers["X-SafeShare-Client-Encrypted"] = "true"

        response = self._client.post("/api/upload/init", json=data, headers=headers)
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
        # ADR-016: bounds how many times this loop will POST /complete again
        # after observing a retryable "failed" status (SCAN_UNAVAILABLE, a
        # transient IO/DB error, etc). The server enforces its own attempt
        # cap independently; this just keeps a permanently broken server
        # from looping the caller forever.
        max_assembly_retries = 3
        assembly_retries = 0

        start_time = time.time()
        while time.time() - start_time < max_wait:
            try:
                status = self.get_upload_status(upload_id)
            except RateLimitError as e:
                # T52: a 429 from the status endpoint only means "poll more
                # slowly" - the upload is still assembling, and its claim
                # code is only ever returned here. Wait (honouring
                # Retry-After) and try again; max_wait still applies.
                remaining = max_wait - (time.time() - start_time)
                time.sleep(max(0.0, min(_rate_limit_poll_delay(e), remaining)))
                continue

            if status.status == "completed" and status.claim_code:
                return UploadResult(
                    claim_code=status.claim_code,
                    download_url=status.download_url or "",
                    file_size=0,  # Not available in status
                    original_filename=status.filename,
                )
            elif status.status == "failed":
                if status.retryable and assembly_retries < max_assembly_retries:
                    assembly_retries += 1
                    time.sleep(poll_interval)
                    try:
                        response = self._client.post(f"/api/upload/complete/{upload_id}")
                        self._handle_response(response)
                    except SafeShareError:
                        # Ignore: the next status read is the source of
                        # truth, whether the retry POST succeeded, re-failed,
                        # or the server answered a terminal error.
                        pass
                    continue

                raise ChunkedUploadError(
                    status.error_message or "Upload failed",
                    error_code=status.error_code,
                )
            elif status.status == "uploading":
                # Should not normally happen while polling (polling only
                # starts after /complete already returned 202) — but
                # defensively, if the row ever falls back to "uploading"
                # underneath us, re-POST /complete (bounded by the same
                # budget as a retryable failure) rather than silently poll a
                # row nothing is ever going to finish on its own.
                if assembly_retries < max_assembly_retries:
                    assembly_retries += 1
                    time.sleep(poll_interval)
                    try:
                        response = self._client.post(f"/api/upload/complete/{upload_id}")
                        self._handle_response(response)
                    except SafeShareError:
                        pass
                    continue
                raise ChunkedUploadError("Upload fell back to uploading state and could not be resumed")

            time.sleep(poll_interval)

        raise ChunkedUploadError("Upload timed out waiting for completion")

    # ==================== File Download ====================

    def download(
        self,
        claim_code: str,
        destination: Union[str, Path, BinaryIO],
        password: Optional[str] = None,
        progress_callback: Optional[DownloadProgressCallback] = None,
        decryption_key: Optional[str] = None,
        overwrite: Optional[bool] = None,
    ) -> Path:
        """
        Download a file by claim code.

        With ``decryption_key`` (the part after "/key/" in an encrypted share
        link) the file is downloaded into memory, decrypted, and written
        decrypted (mode 0600); an existing destination is then refused unless
        ``overwrite=True``, and checked before downloading so a limited
        download isn't used up. (Plain downloads keep their old behaviour of
        replacing the destination unless ``overwrite=False``.)

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

        if decryption_key is not None:
            if isinstance(destination, (str, Path)):
                dest_path = Path(destination)
                if dest_path.is_symlink():
                    raise DownloadError(f"Destination is a symbolic link, refusing to write to it: {dest_path}")
                if dest_path.exists() and not overwrite:
                    raise DownloadError(f"Destination already exists: {dest_path}")
                f = self.download_decrypted(claim_code, decryption_key, password, progress_callback)
                try:
                    _write_private(dest_path, f.data, bool(overwrite))
                except OSError as err:
                    raise DownloadError(f"Writing the file failed: {err}") from err
                return dest_path.resolve()
            f = self.download_decrypted(claim_code, decryption_key, password, progress_callback)
            destination.write(f.data)
            return Path(getattr(destination, "name", "download"))

        if overwrite is False and isinstance(destination, (str, Path)) and Path(destination).exists():
            raise DownloadError(f"Destination already exists: {destination}")

        # The password goes in the X-File-Password header; the ?password=
        # query parameter is deprecated server-side because URLs end up in
        # proxy logs and history. The client doesn't follow redirects, so the
        # header can't be forwarded to another host.
        url = f"/api/claim/{claim_code}"
        headers = {"X-File-Password": password} if password else {}

        try:
            # Use streaming download
            with self._client.stream("GET", url, headers=headers) as response:
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

    def download_decrypted(
        self,
        claim_code: str,
        key: str,
        password: Optional[str] = None,
        progress_callback: Optional[DownloadProgressCallback] = None,
    ) -> DecryptedFile:
        """Download an end-to-end encrypted file into memory and decrypt it.

        ``key`` is the base64url key from the share link (see
        safeshare.e2e.parse_share_url). Handles every format the web app
        writes. The returned filename comes from the uploader; use
        safeshare.e2e.safe_filename() before saving under it.
        """
        self._validate_claim_code(claim_code)
        raw_key = e2e.decode_key(key)
        info = self.get_file_info(claim_code)
        limit = info.file_size
        if limit < 0 or limit > e2e.MAX_ENCRYPTED_PAYLOAD + e2e.CIPHERTEXT_OVERHEAD:
            raise DownloadError(f"The server reports {limit} bytes; decrypting holds the whole file in memory")
        headers = {"X-File-Password": password} if password else {}
        try:
            data = self._download_bounded(claim_code, headers, limit, progress_callback)
        except httpx.HTTPError as err:
            raise DownloadError(f"Download failed: {err}") from err
        plaintext = e2e.decrypt_blob(raw_key, data)
        return e2e.unwrap_download(plaintext, info.original_filename)

    def _download_bounded(
        self,
        claim_code: str,
        headers: dict,
        limit: int,
        progress_callback: Optional[DownloadProgressCallback],
    ) -> bytes:
        """Download a claim into memory, refusing more than ``limit`` bytes."""
        buf = bytearray()
        with self._client.stream("GET", f"/api/claim/{claim_code}", headers=headers) as response:
            if response.status_code >= 400:
                response.read()
                self._handle_response(response)
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise DownloadError(f"The server sent {declared} bytes but reported {limit}")
            start = time.time()
            for chunk in response.iter_bytes(chunk_size=65536):
                buf += chunk
                if len(buf) > limit:
                    raise DownloadError(f"The server sent more than the {limit} bytes it reported")
                if progress_callback:
                    elapsed = time.time() - start
                    progress_callback(
                        DownloadProgress.from_bytes(len(buf), limit, len(buf) / elapsed if elapsed > 0 else None)
                    )
        return bytes(buf)

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
        headers = {"X-File-Password": password} if password else {}

        response = self._client.get(url, headers=headers)
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

        # httpx.Client.delete() doesn't accept a body (json/data/content) —
        # only request() does — so a DELETE-with-JSON-body call must go
        # through the generic request() method.
        response = self._client.request(
            "DELETE",
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
