from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

SCAN_TIMEOUT    = 120  # seconds
EXTRACT_TIMEOUT = 300  # seconds

_FINDING_RE = re.compile(r'^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$')


class BinwalkNotFoundError(RuntimeError):
    pass


class BinwalkTimeoutError(RuntimeError):
    pass


class BinwalkError(RuntimeError):
    pass


def _find_binwalk() -> str:
    exe = shutil.which("binwalk")
    if exe is None:
        raise BinwalkNotFoundError("binwalk not found in PATH")
    return exe


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_output(stdout: str) -> list[dict]:
    findings = []
    for line in stdout.splitlines():
        m = _FINDING_RE.match(line.strip())
        if m:
            findings.append({
                "offset": int(m.group(1)),
                "hex_offset": m.group(2),
                "description": m.group(3).strip(),
            })
    return findings


def scan(path: Path, timeout: int = SCAN_TIMEOUT) -> dict:
    """Run binwalk magic scan only (no extraction).

    Never raises — errors are captured in the "error" field so the
    overall scan pipeline can continue even when binwalk is unavailable.

    Returns:
        {"findings": list[dict], "extracted": [], "error": str | None}
    """
    try:
        exe = _find_binwalk()
    except BinwalkNotFoundError as e:
        return {"findings": [], "extracted": [], "error": str(e)}

    try:
        result = subprocess.run(
            [exe, "-B", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"findings": [], "extracted": [], "error": f"binwalk scan timed out after {timeout}s"}
    except Exception as e:
        return {"findings": [], "extracted": [], "error": f"binwalk error: {e}"}

    if result.returncode not in (0, 1):
        return {
            "findings": [],
            "extracted": [],
            "error": f"binwalk exited with code {result.returncode}: {result.stderr.strip()}",
        }

    return {
        "findings": _parse_output(result.stdout),
        "extracted": [],
        "error": None,
    }


def extract(path: Path, output_dir: Path, timeout: int = EXTRACT_TIMEOUT) -> dict:
    """Run binwalk extraction mode.

    IMPORTANT: This function ONLY extracts files and lists their paths.
    It NEVER executes any extracted file. Callers must not execute
    any file from output_dir.

    Returns:
        {"findings": list[dict], "extracted": list[str], "error": str | None}
    """
    try:
        exe = _find_binwalk()
    except BinwalkNotFoundError as e:
        return {"findings": [], "extracted": [], "error": str(e)}

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [exe, "-e", "--run-as=root", "-C", str(output_dir), str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"findings": [], "extracted": [], "error": f"binwalk extract timed out after {timeout}s"}
    except Exception as e:
        return {"findings": [], "extracted": [], "error": f"binwalk error: {e}"}

    if result.returncode not in (0, 1):
        return {
            "findings": [],
            "extracted": [],
            "error": f"binwalk exited with code {result.returncode}: {result.stderr.strip()}",
        }

    extracted = []
    for p in sorted(output_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            sha256 = _hash_file(p)
            size = p.stat().st_size
        except Exception:
            sha256 = None
            size = None
        extracted.append({
            "path": str(p),
            "name": p.name,
            "size": size,
            "sha256": sha256,
        })

    return {
        "findings": _parse_output(result.stdout),
        "extracted": extracted,
        "error": None,
    }
