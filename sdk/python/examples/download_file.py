#!/usr/bin/env python3
"""
File download example.

This example demonstrates downloading files from SafeShare with progress tracking.
"""

import os
import sys
from pathlib import Path

from safeshare import SafeShareClient
from safeshare.exceptions import NotFoundError, PasswordRequiredError, DownloadLimitReachedError
from safeshare.models import DownloadProgress


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

    # Parse arguments
    if len(sys.argv) < 2:
        print("Usage: python download_file.py <claim_code> [destination] [password]")
        print("\nArguments:")
        print("  claim_code   - File claim code to download")
        print("  destination  - Destination path (optional, uses original filename)")
        print("  password     - Password for protected files (optional)")
        print("\nEnvironment variables:")
        print("  SAFESHARE_URL - SafeShare server URL (default: http://localhost:8080)")
        sys.exit(1)

    claim_code = sys.argv[1]
    destination = sys.argv[2] if len(sys.argv) > 2 else None
    password = sys.argv[3] if len(sys.argv) > 3 else None

    # Progress callback
    def on_progress(progress: DownloadProgress):
        if progress.total_bytes:
            bar_width = 40
            filled = int(bar_width * (progress.percentage or 0) / 100)
            bar = "=" * filled + "-" * (bar_width - filled)
            speed_str = ""
            if progress.speed_bps:
                speed_str = f" {format_size(int(progress.speed_bps))}/s"
            print(
                f"\rDownloading: [{bar}] {progress.percentage:.1f}%{speed_str}",
                end="",
                flush=True,
            )
        else:
            # Unknown size - just show bytes downloaded
            print(
                f"\rDownloaded: {format_size(progress.bytes_downloaded)}",
                end="",
                flush=True,
            )

    with SafeShareClient(base_url=base_url) as client:
        # First, get file info
        print(f"Getting file info for {claim_code}...")
        try:
            info = client.get_file_info(claim_code, password=password)
        except PasswordRequiredError:
            print("Error: This file is password protected.")
            if not password:
                print("Please provide the password as the third argument.")
            else:
                print("The provided password is incorrect.")
            sys.exit(1)
        except NotFoundError:
            print("Error: File not found or has expired.")
            sys.exit(1)
        except DownloadLimitReachedError:
            print("Error: Download limit has been reached for this file.")
            sys.exit(1)

        print(f"\nFile: {info.original_filename}")
        print(f"Size: {format_size(info.file_size)}")
        if info.downloads_remaining is not None:
            print(f"Downloads remaining: {info.downloads_remaining}")

        # Determine destination
        if destination is None:
            destination = info.original_filename

        dest_path = Path(destination)
        if dest_path.exists():
            response = input(f"\n{dest_path} already exists. Overwrite? [y/N] ")
            if response.lower() != "y":
                print("Cancelled.")
                sys.exit(0)

        # Download
        print(f"\nDownloading to {dest_path}...")
        try:
            client.download(
                claim_code,
                dest_path,
                password=password,
                progress_callback=on_progress,
            )
        except PasswordRequiredError:
            print("\nError: Password required.")
            sys.exit(1)
        except NotFoundError:
            print("\nError: File not found or expired.")
            sys.exit(1)

        print("\n\nDownload complete!")
        print(f"Saved to: {dest_path.absolute()}")


if __name__ == "__main__":
    main()
