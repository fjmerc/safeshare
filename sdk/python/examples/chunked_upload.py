#!/usr/bin/env python3
"""
Chunked upload example for large files.

This example demonstrates uploading large files with progress tracking.
The SDK automatically uses chunked upload for files above the server threshold.
"""

import os
import sys
from pathlib import Path

from safeshare import SafeShareClient, UploadProgress


def format_size(size_bytes: int) -> str:
    """Format byte size to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def main():
    # Get configuration from environment
    base_url = os.environ.get("SAFESHARE_URL", "http://localhost:8080")
    api_token = os.environ.get("SAFESHARE_TOKEN")

    # Check for file argument
    if len(sys.argv) < 2:
        print("Usage: python chunked_upload.py <file_path>")
        print("\nEnvironment variables:")
        print("  SAFESHARE_URL   - SafeShare server URL (default: http://localhost:8080)")
        print("  SAFESHARE_TOKEN - API token for authentication (optional)")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    file_size = file_path.stat().st_size
    print(f"File: {file_path.name}")
    print(f"Size: {format_size(file_size)}")

    # Progress callback with detailed info
    def on_progress(progress: UploadProgress):
        bar_width = 30
        filled = int(bar_width * progress.percentage / 100)
        bar = "=" * filled + "-" * (bar_width - filled)

        # Show chunk progress for chunked uploads
        if progress.total_chunks > 1:
            chunk_info = f" (chunk {progress.chunks_completed}/{progress.total_chunks})"
        else:
            chunk_info = ""

        # Show speed if available
        if progress.speed_bps:
            speed_str = f" {format_size(int(progress.speed_bps))}/s"
        else:
            speed_str = ""

        print(
            f"\r[{bar}] {progress.percentage:.1f}%{chunk_info}{speed_str}",
            end="",
            flush=True,
        )

    # Upload file
    print(f"\nUploading to {base_url}...")

    with SafeShareClient(base_url=base_url, api_token=api_token) as client:
        # Get server config to show threshold
        config = client.get_config()
        if file_size >= config.chunked_upload_threshold:
            print(f"Using chunked upload (threshold: {format_size(config.chunked_upload_threshold)})")
            print(f"Chunk size: {format_size(config.chunk_size)}")
        else:
            print("Using simple upload")

        result = client.upload(
            file_path,
            expires_in_hours=168,  # Expire in 7 days
            progress_callback=on_progress,
        )

    print("\n")  # New lines after progress bar
    print("Upload successful!")
    print(f"  Claim code: {result.claim_code}")
    print(f"  Download URL: {result.download_url}")
    if result.expires_at:
        print(f"  Expires at: {result.expires_at}")
    if result.sha256_hash:
        print(f"  SHA-256: {result.sha256_hash}")


if __name__ == "__main__":
    main()
