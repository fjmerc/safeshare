"""
Tests for SafeShare client.
"""

import pytest
from pytest_httpx import HTTPXMock

from safeshare import SafeShareClient
from safeshare.exceptions import (
    AuthenticationError,
    DownloadLimitReachedError,
    FileQuarantinedError,
    MalwareDetectedError,
    NotFoundError,
    RateLimitError,
    ScanFailedError,
    ScanPendingError,
    ScanUnavailableError,
    UnscannableUploadError,
    UploadError,
)
from safeshare.models import UploadProgress


class TestClientInitialization:
    """Test client initialization."""

    def test_init_with_token(self):
        """Test client initialization with API token."""
        client = SafeShareClient(
            base_url="https://example.com",
            api_token="safeshare_test_token",
        )
        assert client.base_url == "https://example.com"
        assert client.api_token == "safeshare_test_token"
        client.close()

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from base URL."""
        client = SafeShareClient(base_url="https://example.com/")
        assert client.base_url == "https://example.com"
        client.close()

    def test_context_manager(self):
        """Test client as context manager."""
        with SafeShareClient(base_url="https://example.com") as client:
            assert client is not None


class TestGetConfig:
    """Test configuration fetching."""

    def test_get_config(self, httpx_mock: HTTPXMock):
        """Test fetching server configuration."""
        httpx_mock.add_response(
            url="https://example.com/api/config",
            json={
                "version": "2.8.4",
                "max_file_size": 104857600,
                "default_expiration_hours": 24,
                "max_expiration_hours": 168,
                "chunked_upload_enabled": True,
                "chunked_upload_threshold": 104857600,
                "chunk_size": 10485760,
                "require_auth_for_upload": False,
            },
        )

        with SafeShareClient(base_url="https://example.com") as client:
            config = client.get_config()
            assert config.version == "2.8.4"
            assert config.max_file_size == 104857600
            assert config.chunked_upload_enabled is True


class TestUpload:
    """Test file upload."""

    def test_simple_upload(self, httpx_mock: HTTPXMock, tmp_path):
        """Test simple file upload."""
        # Mock config
        httpx_mock.add_response(
            url="https://example.com/api/config",
            json={
                "version": "2.8.4",
                "max_file_size": 104857600,
                "default_expiration_hours": 24,
                "max_expiration_hours": 168,
                "chunked_upload_enabled": True,
                "chunked_upload_threshold": 104857600,
                "chunk_size": 10485760,
                "require_auth_for_upload": False,
            },
        )

        # Mock upload
        httpx_mock.add_response(
            url="https://example.com/api/upload",
            method="POST",
            status_code=201,
            json={
                "claim_code": "ABC123",
                "download_url": "https://example.com/api/claim/ABC123",
                "expires_at": "2025-11-28T12:00:00Z",
                "max_downloads": 5,
                "file_size": 100,
                "original_filename": "test.txt",
                "sha256_hash": "abc123",
            },
        )

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        with SafeShareClient(base_url="https://example.com") as client:
            result = client.upload(
                test_file,
                expires_in_hours=24,
                max_downloads=5,
            )
            assert result.claim_code == "ABC123"
            assert result.original_filename == "test.txt"

    def test_upload_with_progress_callback(self, httpx_mock: HTTPXMock, tmp_path):
        """Test upload with progress callback."""
        # Mock config
        httpx_mock.add_response(
            url="https://example.com/api/config",
            json={
                "version": "2.8.4",
                "max_file_size": 104857600,
                "default_expiration_hours": 24,
                "max_expiration_hours": 168,
                "chunked_upload_enabled": True,
                "chunked_upload_threshold": 104857600,
                "chunk_size": 10485760,
                "require_auth_for_upload": False,
            },
        )

        # Mock upload
        httpx_mock.add_response(
            url="https://example.com/api/upload",
            method="POST",
            status_code=201,
            json={
                "claim_code": "ABC123",
                "download_url": "https://example.com/api/claim/ABC123",
                "file_size": 13,
                "original_filename": "test.txt",
            },
        )

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        progress_updates = []

        def on_progress(progress: UploadProgress):
            progress_updates.append(progress)

        with SafeShareClient(base_url="https://example.com") as client:
            client.upload(test_file, progress_callback=on_progress)

        assert len(progress_updates) >= 1
        assert progress_updates[-1].percentage == 100.0

    def test_upload_file_not_found(self):
        """Test upload with non-existent file."""
        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(UploadError, match="File not found"):
                client.upload("/nonexistent/file.txt")


class TestDownload:
    """Test file download."""

    def test_download_file(self, httpx_mock: HTTPXMock, tmp_path):
        """Test file download."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123",
            content=b"Hello, World!",
            headers={
                "content-type": "text/plain",
                "content-length": "13",
            },
        )

        dest_file = tmp_path / "downloaded.txt"

        with SafeShareClient(base_url="https://example.com") as client:
            result = client.download("ABC123", dest_file)
            assert result == dest_file
            assert dest_file.read_text() == "Hello, World!"

    def test_download_with_password(self, httpx_mock: HTTPXMock, tmp_path):
        """Test download with password."""
        # Password must travel in the X-File-Password header, not the URL.
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123",
            match_headers={"X-File-Password": "secret"},
            content=b"Secret content",
        )

        dest_file = tmp_path / "downloaded.txt"

        with SafeShareClient(base_url="https://example.com") as client:
            client.download("ABC123", dest_file, password="secret")
            assert dest_file.read_text() == "Secret content"

    def test_download_not_found(self, httpx_mock: HTTPXMock, tmp_path):
        """Test download with invalid claim code."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/INVALID",
            status_code=404,
            json={"error": "File not found"},
        )

        dest_file = tmp_path / "downloaded.txt"

        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(NotFoundError):
                client.download("INVALID", dest_file)


class TestFileInfo:
    """Test file info retrieval."""

    def test_get_file_info(self, httpx_mock: HTTPXMock):
        """Test getting file metadata."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123/info",
            json={
                "claim_code": "ABC123",
                "original_filename": "test.txt",
                "file_size": 1024,
                "created_at": "2025-11-27T12:00:00Z",
                "expires_at": "2025-11-28T12:00:00Z",
                "download_count": 2,
                "max_downloads": 5,
                "downloads_remaining": 3,
                "password_protected": False,
            },
        )

        with SafeShareClient(base_url="https://example.com") as client:
            info = client.get_file_info("ABC123")
            assert info.claim_code == "ABC123"
            assert info.original_filename == "test.txt"
            assert info.downloads_remaining == 3

    def test_get_file_info_scan_status(self, httpx_mock: HTTPXMock):
        """Test that ADR-015 scan_status/download_available fields (T39) are
        parsed from the /info response."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123/info",
            json={
                "claim_code": "ABC123",
                "original_filename": "test.txt",
                "file_size": 1024,
                "created_at": "2025-11-27T12:00:00Z",
                "expires_at": "2025-11-28T12:00:00Z",
                "download_count": 0,
                "max_downloads": None,
                "downloads_remaining": None,
                "password_protected": False,
                "scan_status": "clean",
                "download_available": True,
            },
        )

        with SafeShareClient(base_url="https://example.com") as client:
            info = client.get_file_info("ABC123")
            assert info.scan_status == "clean"
            assert info.download_available is True

    def test_get_file_info_scan_status_absent(self, httpx_mock: HTTPXMock):
        """scan_status/download_available must be optional so the SDK still
        parses responses from servers/legacy files that don't send them."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123/info",
            json={
                "claim_code": "ABC123",
                "original_filename": "test.txt",
                "file_size": 1024,
                "created_at": "2025-11-27T12:00:00Z",
                "download_count": 0,
                "password_protected": False,
            },
        )

        with SafeShareClient(base_url="https://example.com") as client:
            info = client.get_file_info("ABC123")
            assert info.scan_status is None
            assert info.download_available is None


class TestFileManagement:
    """Test file management operations."""

    def test_list_files(self, httpx_mock: HTTPXMock):
        """Test listing user's files."""
        httpx_mock.add_response(
            url="https://example.com/api/user/files?limit=50&offset=0",
            json={
                "files": [
                    {
                        "id": 1,
                        "claim_code": "ABC123",
                        "original_filename": "test.txt",
                        "file_size": 1024,
                        "created_at": "2025-11-27T12:00:00Z",
                        "download_count": 0,
                        "completed_downloads": 0,
                        "password_protected": False,
                    }
                ],
                "total": 1,
                "limit": 50,
                "offset": 0,
            },
        )

        with SafeShareClient(
            base_url="https://example.com",
            api_token="safeshare_test_token",
        ) as client:
            result = client.list_files()
            assert result.total == 1
            assert len(result.files) == 1
            assert result.files[0].claim_code == "ABC123"

    def test_list_files_requires_auth(self):
        """Test that list_files requires authentication."""
        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(AuthenticationError, match="API token required"):
                client.list_files()

    def test_delete_file(self, httpx_mock: HTTPXMock):
        """Test deleting a file."""
        httpx_mock.add_response(
            url="https://example.com/api/user/files/delete",
            method="DELETE",
            match_json={"file_id": 1},
            status_code=200,
        )

        with SafeShareClient(
            base_url="https://example.com",
            api_token="safeshare_test_token",
        ) as client:
            # Should not raise, and must send the file ID in the JSON body
            client.delete_file(1)

    def test_error_with_non_string_code_falls_back_to_status(self, httpx_mock: HTTPXMock):
        """A malformed (non-string) error code must not break error mapping."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/abc123/info",
            status_code=404,
            json={"error": "not found", "code": ["unexpected"]},
        )

        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(NotFoundError):
                client.get_file_info("abc123")

    def test_rename_file(self, httpx_mock: HTTPXMock):
        """Test renaming a file."""
        httpx_mock.add_response(
            url="https://example.com/api/user/files/rename",
            method="POST",
            status_code=200,
        )

        with SafeShareClient(
            base_url="https://example.com",
            api_token="safeshare_test_token",
        ) as client:
            # Should not raise
            client.rename_file(1, "new_name.txt")


class TestErrorHandling:
    """Test error handling."""

    def test_authentication_error(self, httpx_mock: HTTPXMock):
        """Test authentication error handling."""
        httpx_mock.add_response(
            url="https://example.com/api/user/files?limit=50&offset=0",
            status_code=401,
            json={"error": "Invalid API token"},
        )

        with SafeShareClient(
            base_url="https://example.com",
            api_token="invalid_token",
        ) as client:
            with pytest.raises(AuthenticationError):
                client.list_files()

    def test_rate_limit_error(self, httpx_mock: HTTPXMock):
        """Test rate limit error handling."""
        httpx_mock.add_response(
            url="https://example.com/api/config",
            json={
                "version": "2.8.4",
                "max_file_size": 104857600,
                "default_expiration_hours": 24,
                "max_expiration_hours": 168,
                "chunked_upload_enabled": True,
                "chunked_upload_threshold": 104857600,
                "chunk_size": 10485760,
                "require_auth_for_upload": False,
            },
        )
        httpx_mock.add_response(
            url="https://example.com/api/upload",
            method="POST",
            status_code=429,
            json={"error": "Rate limit exceeded"},
        )

        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(RateLimitError):
                import io

                client.upload(io.BytesIO(b"test"), filename="test.txt")


class TestScanErrorHandling:
    """Test ADR-015 malware-scan error_code -> exception mapping (T39).

    Mirrors sdk/go/errors.go's newAPIError code-first dispatch: several of
    these codes share an HTTP status with an older, differently-meaning
    error, so the exception class is keyed off error_code, not status_code.
    """

    @pytest.mark.parametrize(
        "status_code,code,expected_exc",
        [
            (422, "MALWARE_DETECTED", MalwareDetectedError),
            (410, "FILE_QUARANTINED", FileQuarantinedError),
            (423, "SCAN_PENDING", ScanPendingError),
            (503, "SCAN_UNAVAILABLE", ScanUnavailableError),
            (403, "SCAN_FAILED", ScanFailedError),
            (422, "UNSCANNABLE_UPLOAD", UnscannableUploadError),
        ],
    )
    def test_scan_error_codes(self, httpx_mock, status_code, code, expected_exc):
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123/info",
            status_code=status_code,
            json={"error": "scan-related failure", "code": code},
        )

        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(expected_exc) as excinfo:
                client.get_file_info("ABC123")
            assert excinfo.value.error_code == code
            assert excinfo.value.status_code == status_code

    def test_file_quarantined_not_confused_with_download_limit_reached(self, httpx_mock):
        """Both FILE_QUARANTINED and the legacy download-limit-reached case
        use HTTP 410 — the error_code must disambiguate, not the status."""
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123/info",
            status_code=410,
            json={"error": "download limit reached", "code": "download_limit_reached"},
        )

        with SafeShareClient(base_url="https://example.com") as client:
            with pytest.raises(DownloadLimitReachedError):
                client.get_file_info("ABC123")


class TestWaitForCompletionRateLimit:
    """T52: a 429 from the status endpoint must not abort an assembling upload."""

    UPLOAD_ID = "550e8400-e29b-41d4-a716-446655440052"

    def test_keeps_polling_through_429(self, httpx_mock: HTTPXMock, monkeypatch):
        import safeshare.client as client_module

        sleeps = []
        monkeypatch.setattr(client_module.time, "sleep", lambda s: sleeps.append(s))
        url = f"https://example.com/api/upload/status/{self.UPLOAD_ID}"
        for _ in range(2):
            httpx_mock.add_response(
                url=url,
                status_code=429,
                headers={"Retry-After": "30"},
                json={"error": "Rate limit exceeded", "code": "RATE_LIMITED"},
            )
        httpx_mock.add_response(
            url=url,
            json={
                "upload_id": self.UPLOAD_ID,
                "filename": "f.bin",
                "status": "completed",
                "chunks_received": 1,
                "total_chunks": 1,
                "complete": True,
                "claim_code": "AbCdEfGh12345678",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        )

        client = SafeShareClient(base_url="https://example.com")
        result = client._wait_for_completion(self.UPLOAD_ID)
        client.close()

        assert result.claim_code == "AbCdEfGh12345678"
        assert sleeps == [30.0, 30.0]

    def test_rate_limit_poll_delay_bounds(self):
        from safeshare.client import _rate_limit_poll_delay

        assert _rate_limit_poll_delay(RateLimitError("x")) == 15.0
        assert _rate_limit_poll_delay(RateLimitError("x", retry_after=5)) == 15.0
        assert _rate_limit_poll_delay(RateLimitError("x", retry_after=45)) == 45.0
        assert _rate_limit_poll_delay(RateLimitError("x", retry_after=600)) == 60.0
