"""Application settings — all secrets come from environment / .env file."""
from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HELIX_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # JWT
    secret_key: str = "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Database
    database_url: str = "sqlite:///./helix.db"

    # Storage
    upload_dir: Path = Path("./uploads")
    output_dir: Path = Path("./outputs")
    max_file_size: int = 500 * 1024 * 1024  # 500 MB

    # Extensions that are allowed for upload (empty set = allow all)
    allowed_extensions: set[str] = {
        ".bin", ".fw", ".img", ".hex", ".rom", ".elf",
        ".axf", ".srec", ".mot", ".ihx",
    }

    # Scanner execution
    use_docker_sandbox: bool = False
    scan_timeout: int = 300  # seconds
    docker_image: str = "helix-guard-scanner:latest"
    docker_memory: str = "1g"
    docker_cpus: str = "1.0"

    # Faz 5 — async job queue. When false (default), scans run in an
    # in-process daemon thread, same as Faz 4 — no Redis/worker required.
    # When true, scans are dispatched as Celery tasks instead.
    use_celery: bool = False
    redis_url: str = "redis://localhost:6379/0"

    # Faz 6 — object storage. When false (default), uploads are kept on
    # local disk under upload_dir, same as Faz 4. When true, firmware files
    # are stored in MinIO (S3-compatible) instead; the scanner downloads a
    # temporary local copy for analysis and discards it afterward.
    use_object_storage: bool = False
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "helixadmin"
    minio_secret_key: str = "helixsecret"
    minio_bucket: str = "helix-firmware"
    minio_secure: bool = False

    # Default bootstrap admin (change before first run)
    admin_username: str = "admin"
    admin_password: str = "changeme"
    admin_email: str = "admin@helix.local"

    @field_validator("upload_dir", "output_dir", mode="before")
    @classmethod
    def _to_path(cls, v: object) -> Path:
        return Path(v)


settings = Settings()
