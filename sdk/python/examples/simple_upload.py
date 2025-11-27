#!/usr/bin/env python3
"""
Simple file upload example.

This example demonstrates basic file upload to SafeShare.
"""

import os
import sys
from pathlib import Path

from safeshare import SafeShareClient, UploadProgress


def main():
    # Get configuration from environment
    base_url = os.environ.get("SAFESHARE_URL", "http://localhost:8080")
    api_token = os.environ.get("SAFESHARE_TOKEN")

    # Check for file argument
    if len(sys.argv) < 2:
        print("Usage: python simple_upload.py <file_path>")
        print("\nEnvironment variables:")
        print("  SAFESHARE_URL   - SafeShare server URL (default: http://localhost:8080)")
        print("  SAFESHARE_TOKEN - API token for authentication (optional)")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    # Progress callback
    def on_progress(progress: UploadProgress):
        bar_width = 40
        filled = int(bar_width * progress.percentage / 100)
        bar = "=" * filled + "-" * (bar_width - filled)
        print(f"\rUploading: [{bar}] {progress.percentage:.1f}%", end="", flush=True)

    # Upload file
    print(f"Uploading {file_path.name} to {base_url}...")

    with SafeShareClient(base_url=base_url, api_token=api_token) as client:
        result = client.upload(
            file_path,
            expires_in_hours=24,  # Expire in 24 hours
            progress_callback=on_progress,
        )

    print()  # New line after progress bar
    print(f"\nUpload successful!")
    print(f"  Claim code: {result.claim_code}")
    print(f"  Download URL: {result.download_url}")
    if result.expires_at:
        print(f"  Expires at: {result.expires_at}")
    print(f"  File size: {result.file_size:,} bytes")


if __name__ == "__main__":
    main()
