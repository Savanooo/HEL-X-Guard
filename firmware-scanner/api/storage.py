"""File upload storage helpers.

Two backends, selected by HELIX_USE_OBJECT_STORAGE:
  - local disk (default, Faz 4 behavior) — stored_path is a real filesystem path.
  - MinIO / S3-compatible (Faz 6) — stored_path is an object key; the scanner
    downloads a temporary local copy for analysis and discards it afterward.

Callers (runner.py, routers/scans.py) only see `stored_path: str` and the
functions below — they never need to know which backend is active.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from .config import settings

_minio_client = None  # lazily constructed; type is minio.Minio when set


def _ensure_dirs() -> None:
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)


def _get_minio_client():
    global _minio_client
    if _minio_client is None:
        from minio import Minio

        _minio_client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
        if not _minio_client.bucket_exists(settings.minio_bucket):
            _minio_client.make_bucket(settings.minio_bucket)
    return _minio_client


async def _stream_to_disk(file: UploadFile, dest: Path) -> int:
    """Stream-write the upload to `dest`, enforcing max_file_size. Returns byte count."""
    received = 0
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(65_536)
            if not chunk:
                break
            received += len(chunk)
            if received > settings.max_file_size:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds the {settings.max_file_size // (1024 * 1024)} MB limit",
                )
            out.write(chunk)
    return received


async def save_upload(scan_id: str, file: UploadFile) -> tuple[str, int]:
    """Validate and persist the uploaded firmware file.

    Returns (stored_path, size_bytes). `stored_path` is a local filesystem
    path in the default backend, or a MinIO object key when object storage
    is enabled — callers must treat it as an opaque reference and use the
    other functions in this module to work with it.

    Raises HTTPException on extension/size violations.
    """
    _ensure_dirs()

    original_name = file.filename or "firmware.bin"
    suffix = Path(original_name).suffix.lower()

    if settings.allowed_extensions and suffix and suffix not in settings.allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Extension '{suffix}' not allowed. "
                f"Allowed: {sorted(settings.allowed_extensions)}"
            ),
        )

    object_key = f"{scan_id}{suffix or '.bin'}"
    local_tmp = settings.upload_dir / object_key
    size = await _stream_to_disk(file, local_tmp)

    if not settings.use_object_storage:
        return str(local_tmp), size

    client = _get_minio_client()
    client.fput_object(settings.minio_bucket, object_key, str(local_tmp))
    local_tmp.unlink(missing_ok=True)
    return object_key, size


def exists(stored_path: str) -> bool:
    """True if the referenced firmware file/object is still retrievable."""
    if not settings.use_object_storage:
        return Path(stored_path).exists()

    from minio.error import S3Error

    try:
        _get_minio_client().stat_object(settings.minio_bucket, stored_path)
        return True
    except S3Error:
        return False


def resolve_for_analysis(stored_path: str) -> tuple[Path, bool]:
    """Return a local filesystem Path usable by firmware_scanner modules.

    Returns (path, is_temporary). When is_temporary is True, the caller
    must call cleanup_temp() once analysis is done.
    """
    if not settings.use_object_storage:
        return Path(stored_path), False

    client = _get_minio_client()
    tmp_dir = Path(tempfile.mkdtemp(prefix="helix_dl_"))
    local_path = tmp_dir / Path(stored_path).name
    client.fget_object(settings.minio_bucket, stored_path, str(local_path))
    return local_path, True


def cleanup_temp(local_path: Path, is_temporary: bool) -> None:
    """Remove a temporary local copy created by resolve_for_analysis()."""
    if not is_temporary:
        return
    try:
        local_path.unlink(missing_ok=True)
        local_path.parent.rmdir()
    except OSError:
        pass


def get_output_dir(scan_id: str) -> Path:
    d = settings.output_dir / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def cleanup_scan(scan_id: str, stored_path: str | None = None) -> None:
    """Remove the backing firmware file/object and the scan's output directory."""
    if stored_path:
        if settings.use_object_storage:
            try:
                _get_minio_client().remove_object(settings.minio_bucket, stored_path)
            except Exception:
                pass
        else:
            Path(stored_path).unlink(missing_ok=True)

    out_dir = settings.output_dir / scan_id
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
