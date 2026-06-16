"""Host-side Docker sandbox launcher for isolated firmware analysis.

This module is used by higher-level components (API layer, Celery workers)
to run the firmware-scan CLI inside a hardened Docker container.

Security constraints enforced at runtime:
  --network none            no network access
  --read-only               immutable root filesystem
  --tmpfs /tmp              writable temp inside container
  --memory / --cpus         resource limits
  --security-opt            no privilege escalation
  -v firmware:ro            firmware file mounted read-only
  -v output                 output directory (report + extracted files)

Extracted files are never executed — the scanner only reads and lists them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

IMAGE_NAME      = "helix-guard-scanner:latest"
DEFAULT_MEMORY  = "1g"
DEFAULT_CPUS    = "1.0"
DEFAULT_TIMEOUT = 300   # seconds — static scan
EXTRACT_TIMEOUT = 600   # seconds — binwalk extraction mode


class DockerNotFoundError(RuntimeError):
    """Raised when the docker CLI is not found in PATH."""


class DockerImageNotFoundError(RuntimeError):
    """Raised when the scanner image has not been built yet."""


class SandboxError(RuntimeError):
    """Raised when the container exits with a non-zero code or times out."""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _docker_exe() -> str:
    exe = shutil.which("docker")
    if exe is None:
        raise DockerNotFoundError(
            "docker not found in PATH. Install Docker and ensure it is running."
        )
    return exe


def _image_exists(docker: str, image: str) -> bool:
    result = subprocess.run(
        [docker, "image", "inspect", image],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


# ── Public API ────────────────────────────────────────────────────────────────

def build_image(
    context_dir: Path | None = None,
    image: str = IMAGE_NAME,
    *,
    no_cache: bool = False,
) -> None:
    """Build the helix-guard-scanner Docker image.

    Args:
        context_dir: Path containing the Dockerfile. Defaults to the
                     firmware-scanner project root (parent of src/).
        image:       Tag to assign to the built image.
        no_cache:    Pass --no-cache to docker build.
    """
    docker = _docker_exe()

    if context_dir is None:
        # src/firmware_scanner/ → ../../../ → firmware-scanner/
        context_dir = Path(__file__).parent.parent.parent

    cmd = [docker, "build", "-t", image, str(context_dir)]
    if no_cache:
        cmd.append("--no-cache")

    result = subprocess.run(cmd, timeout=600)
    if result.returncode != 0:
        raise SandboxError(f"docker build failed (exit {result.returncode})")


def run_in_docker(
    firmware_path: Path,
    output_dir: Path,
    *,
    image: str = IMAGE_NAME,
    memory: str = DEFAULT_MEMORY,
    cpus: str = DEFAULT_CPUS,
    timeout: int = DEFAULT_TIMEOUT,
    extra_scan_args: list[str] | None = None,
    auto_build: bool = True,
) -> dict:
    """Run firmware-scan inside an isolated Docker container and return the report.

    The firmware file is mounted read-only at /input/<filename>.
    The output directory is mounted read-write at /output.
    The report is written to /output/report.json inside the container.

    Args:
        firmware_path:    Host path to the firmware file to scan.
        output_dir:       Host path where the report (and extracted files) land.
        image:            Docker image name/tag.
        memory:           Container memory limit (e.g. "1g", "512m").
        cpus:             CPU quota (e.g. "1.0", "0.5").
        timeout:          Seconds before the container is killed.
        extra_scan_args:  Additional CLI flags forwarded to firmware-scan
                          (e.g. ["--no-binwalk"] or ["--extract"]).
        auto_build:       If True and the image is missing, build it first.

    Returns:
        Parsed JSON report dict.

    Raises:
        DockerNotFoundError: Docker CLI not available.
        DockerImageNotFoundError: Image missing and auto_build=False.
        SandboxError: Container exited non-zero or timed out.
    """
    docker = _docker_exe()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not _image_exists(docker, image):
        if auto_build:
            build_image(image=image)
        else:
            raise DockerImageNotFoundError(
                f"Image '{image}' not found. Build it first:\n"
                f"  cd firmware-scanner && docker build -t {image} ."
            )

    container_input  = f"/input/{firmware_path.name}"
    container_report = "/output/report.json"

    cmd = [
        docker, "run", "--rm",

        # ── Security constraints ───────────────────────────────────────────
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:size=256m,mode=1777",
        "--security-opt", "no-new-privileges:true",

        # ── Resource limits ────────────────────────────────────────────────
        "--memory", memory,
        "--cpus",   cpus,

        # ── Volume mounts ──────────────────────────────────────────────────
        "-v", f"{firmware_path.resolve()}:{container_input}:ro",
        "-v", f"{output_dir.resolve()}:/output",

        # ── Image and command ──────────────────────────────────────────────
        image,
        container_input,
        "--output", container_report,
    ]

    if extra_scan_args:
        cmd.extend(extra_scan_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SandboxError(f"Container timed out after {timeout}s")
    except Exception as e:
        raise SandboxError(f"docker run error: {e}") from e

    if result.returncode != 0:
        raise SandboxError(
            f"Container exited with code {result.returncode}:\n"
            f"{result.stderr.strip()}"
        )

    report_path = output_dir / "report.json"
    if not report_path.exists():
        raise SandboxError(
            f"Report not found at {report_path} after container exited 0. "
            f"Container stderr:\n{result.stderr.strip()}"
        )

    return json.loads(report_path.read_text(encoding="utf-8"))
