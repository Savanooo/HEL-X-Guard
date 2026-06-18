from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path


def _detect_file_type(path: Path) -> str:
    """Detect MIME type using the `file` CLI. Falls back to application/octet-stream."""
    file_exe = shutil.which("file")
    if file_exe is None:
        return "application/octet-stream"
    try:
        result = subprocess.run(
            [file_exe, "--mime-type", "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "application/octet-stream"


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


def build(
    path: Path,
    hash_result: dict,
    entropy_result: dict,
    strings_result: dict,
    binwalk_result: dict,
    yara_result: dict,
    risk_result: dict,
    elf_result: dict | None = None,
    arch_result: dict | None = None,
    checksec_result: dict | None = None,
    crypto_result: dict | None = None,
    components_result: dict | None = None,
    cert_result: dict | None = None,
) -> dict:
    """Assemble all analysis results into the canonical JSON report."""
    size_bytes = path.stat().st_size

    return {
        "scan_id": str(uuid.uuid4()),
        "file": {
            "name": path.name,
            "path": str(path.resolve()),
            "size": {
                "bytes": size_bytes,
                "human": _human_size(size_bytes),
            },
            "hashes": hash_result,
            "type": _detect_file_type(path),
        },
        "entropy":     entropy_result,
        "strings":     strings_result,
        "binwalk":     binwalk_result,
        "yara":        yara_result,
        "elf":         elf_result if elf_result is not None else {"is_elf": False},
        "arch":        arch_result if arch_result is not None else {"is_bare_metal": False},
        "checksec":    checksec_result if checksec_result is not None else {"is_elf": False},
        "crypto":      crypto_result if crypto_result is not None else {"matches": [], "count": 0},
        "components":  components_result if components_result is not None else {"components": [], "count": 0},
        "certs":       cert_result if cert_result is not None else {"certificates": [], "count": 0},
        "risk":        risk_result,
    }


def write(report: dict, output_path: Path) -> None:
    """Serialize report to JSON and write to output_path."""
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def print_summary(report: dict) -> None:
    """Print a concise human-readable summary using Click colors."""
    try:
        import click
    except ImportError:
        _print_summary_plain(report)
        return

    risk = report.get("risk", {})
    score = risk.get("score", 0)
    level = risk.get("level", "unknown").upper()
    file_info = report.get("file", {})
    strings_info = report.get("strings", {})
    yara_info = report.get("yara", {})

    color_map = {
        "CRITICAL": "bright_red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFORMATIONAL": "cyan",
    }
    color = color_map.get(level, "white")

    click.echo("")
    click.echo(f"  File    : {file_info.get('name', 'unknown')}")
    click.echo(f"  Size    : {file_info.get('size', {}).get('human', '?')}")
    click.echo(f"  Type    : {file_info.get('type', '?')}")
    click.echo(f"  SHA256  : {file_info.get('hashes', {}).get('sha256', '?')}")
    click.echo(f"  Entropy : {report.get('entropy', {}).get('overall', 0):.2f}/8.00"
               f"  [{report.get('entropy', {}).get('interpretation', '')}]")
    click.echo(f"  Strings : {strings_info.get('total', 0)} total,"
               f" {strings_info.get('suspicious_count', 0)} suspicious")
    yara_matches = len(yara_info.get("matches", []))
    click.echo(f"  YARA    : {yara_matches} match(es)")
    click.echo("")
    click.echo(
        "  Risk    : " + click.style(f"{level}  ({score}/100)", fg=color, bold=True)
    )
    for reason in risk.get("reasons", []):
        click.echo(f"            • {reason}")
    click.echo("")


def _print_summary_plain(report: dict) -> None:
    risk = report.get("risk", {})
    file_info = report.get("file", {})
    print(f"File   : {file_info.get('name', 'unknown')}")
    print(f"Risk   : {risk.get('level', '?').upper()} ({risk.get('score', 0)}/100)")
    for reason in risk.get("reasons", []):
        print(f"  - {reason}")
