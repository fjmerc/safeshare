#!/usr/bin/env python3
"""
File management example.

This example demonstrates listing, renaming, and deleting files.
Requires an API token with 'manage' scope.
"""

import os
import sys

from safeshare import SafeShareClient
from safeshare.exceptions import AuthenticationError


def format_size(size_bytes: int) -> str:
    """Format byte size to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def list_files(client: SafeShareClient):
    """List all files."""
    print("\n=== Your Files ===\n")

    result = client.list_files(limit=100)
    print(f"Total files: {result.total}\n")

    if not result.files:
        print("No files found.")
        return

    for f in result.files:
        # Format expiration
        if f.expires_at:
            expires = f.expires_at.strftime("%Y-%m-%d %H:%M")
        else:
            expires = "Never"

        # Format downloads
        if f.max_downloads:
            downloads = f"{f.completed_downloads}/{f.max_downloads}"
        else:
            downloads = str(f.completed_downloads)

        print(f"ID: {f.id}")
        print(f"  Filename: {f.original_filename}")
        print(f"  Claim code: {f.claim_code}")
        print(f"  Size: {format_size(f.file_size)}")
        print(f"  Downloads: {downloads}")
        print(f"  Expires: {expires}")
        print(f"  Password: {'Yes' if f.password_protected else 'No'}")
        print()


def rename_file(client: SafeShareClient, file_id: int, new_name: str):
    """Rename a file."""
    print(f"Renaming file {file_id} to '{new_name}'...")
    client.rename_file(file_id, new_name)
    print("Done!")


def delete_file(client: SafeShareClient, file_id: int):
    """Delete a file."""
    print(f"Deleting file {file_id}...")
    client.delete_file(file_id)
    print("Done!")


def extend_expiration(client: SafeShareClient, file_id: int, hours: int):
    """Extend file expiration."""
    print(f"Extending expiration of file {file_id} by {hours} hours...")
    client.update_expiration(file_id, hours)
    print("Done!")


def regenerate_code(client: SafeShareClient, file_id: int):
    """Regenerate claim code for a file."""
    print(f"Regenerating claim code for file {file_id}...")
    new_code = client.regenerate_claim_code(file_id)
    print(f"New claim code: {new_code}")


def main():
    # Get configuration from environment
    base_url = os.environ.get("SAFESHARE_URL", "http://localhost:8080")
    api_token = os.environ.get("SAFESHARE_TOKEN")

    if not api_token:
        print("Error: SAFESHARE_TOKEN environment variable is required")
        print("\nTo get a token:")
        print("1. Log in to SafeShare web interface")
        print("2. Go to Settings > API Tokens")
        print("3. Create a token with 'manage' scope")
        sys.exit(1)

    # Parse command
    if len(sys.argv) < 2:
        print("Usage: python file_management.py <command> [args]")
        print("\nCommands:")
        print("  list                    - List all your files")
        print("  rename <id> <new_name>  - Rename a file")
        print("  delete <id>             - Delete a file")
        print("  extend <id> <hours>     - Extend file expiration")
        print("  regenerate <id>         - Generate new claim code")
        print("\nEnvironment variables:")
        print("  SAFESHARE_URL   - SafeShare server URL (default: http://localhost:8080)")
        print("  SAFESHARE_TOKEN - API token (required)")
        sys.exit(1)

    command = sys.argv[1].lower()

    try:
        with SafeShareClient(base_url=base_url, api_token=api_token) as client:
            if command == "list":
                list_files(client)

            elif command == "rename":
                if len(sys.argv) < 4:
                    print("Usage: python file_management.py rename <id> <new_name>")
                    sys.exit(1)
                file_id = int(sys.argv[2])
                new_name = sys.argv[3]
                rename_file(client, file_id, new_name)

            elif command == "delete":
                if len(sys.argv) < 3:
                    print("Usage: python file_management.py delete <id>")
                    sys.exit(1)
                file_id = int(sys.argv[2])
                delete_file(client, file_id)

            elif command == "extend":
                if len(sys.argv) < 4:
                    print("Usage: python file_management.py extend <id> <hours>")
                    sys.exit(1)
                file_id = int(sys.argv[2])
                hours = int(sys.argv[3])
                extend_expiration(client, file_id, hours)

            elif command == "regenerate":
                if len(sys.argv) < 3:
                    print("Usage: python file_management.py regenerate <id>")
                    sys.exit(1)
                file_id = int(sys.argv[2])
                regenerate_code(client, file_id)

            else:
                print(f"Unknown command: {command}")
                sys.exit(1)

    except AuthenticationError as e:
        print(f"Authentication error: {e}")
        print("Make sure your token has the 'manage' scope.")
        sys.exit(1)


if __name__ == "__main__":
    main()
