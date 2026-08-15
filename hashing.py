"""
File hashing module for Endpoint Threat Detector.

Calculates SHA-256 hashes for accessible files.
"""

import hashlib


def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """Calculate the SHA-256 hash of an accessible file."""

    if not file_path:
        return None

    try:
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(chunk_size)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError):
        return None
