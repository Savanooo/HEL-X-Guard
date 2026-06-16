from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 8 * 1024  # 8 KB


def hash_file(path: Path, chunk_size: int = CHUNK_SIZE) -> dict:
    """Stream-hash a file in a single pass computing MD5, SHA1, and SHA256.

    Returns:
        {"md5": str, "sha1": str, "sha256": str}
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
