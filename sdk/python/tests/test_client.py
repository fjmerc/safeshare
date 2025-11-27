"""
Tests for SafeShare client.
"""

import pytest
from pytest_httpx import HTTPXMock

from safeshare import SafeShareClient
from safeshare.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
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
        httpx_mock.add_response(
            url="https://example.com/api/claim/ABC123?password=secret",
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
            status_code=200,
        )

        with SafeShareClient(
            base_url="https://example.com",
            api_token="safeshare_test_token",
        ) as client:
            # Should not raise
            client.delete_file(1)

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
