from __future__ import annotations

import sys
from pathlib import Path

import click

from firmware_scanner import hashing, entropy, strings_scan, elf_analysis
from firmware_scanner import binwalk_runner, yara_runner, risk_scoring, report

DEFAULT_RULES = Path(__file__).parent.parent.parent / "rules" / "firmware_rules.yar"


@click.command(name="firmware-scan")
@click.argument(
    "firmware_file",
    type=click.Path(exists=True, readable=True, path_type=Path),
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write JSON report to FILE (default: print human summary to stdout)",
)
@click.option(
    "--no-binwalk",
    is_flag=True,
    default=False,
    help="Skip binwalk scan (useful when binwalk is not installed)",
)
@click.option(
    "--extract",
    is_flag=True,
    default=False,
    help="Run binwalk in extraction mode (files extracted but NEVER executed)",
)
@click.option(
    "--extract-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory for binwalk extraction (default: <firmware_file>_extracted/)",
)
@click.option(
    "--rules", "-r",
    type=click.Path(exists=True, readable=True, path_type=Path),
    default=None,
    help="Path to custom YARA rules file",
)
@click.option(
    "--block-size",
    type=int,
    default=1024,
    show_default=True,
    help="Entropy analysis block size in bytes",
)
@click.option(
    "--min-string-len",
    type=int,
    default=6,
    show_default=True,
    help="Minimum string length for extraction",
)
@click.version_option(version="0.1.0", prog_name="firmware-scan")
def main(
    firmware_file: Path,
    output: Path | None,
    no_binwalk: bool,
    extract: bool,
    extract_dir: Path | None,
    rules: Path | None,
    block_size: int,
    min_string_len: int,
) -> None:
    """HELİX-Guard: Static firmware binary security scanner.

    Analyzes FIRMWARE_FILE without executing any extracted content.
    """
    def log(msg: str) -> None:
        click.echo(f"[*] {msg}", err=True)

    log(f"Scanning: {firmware_file.name}  ({firmware_file.stat().st_size:,} bytes)")

    # 1. Hashing
    log("Computing hashes...")
    hash_result = hashing.hash_file(firmware_file)

    # 2. Entropy
    log("Analyzing entropy...")
    entropy_result = entropy.analyze(firmware_file, block_size=block_size)

    # 3. Strings
    log("Extracting strings...")
    strings_result = strings_scan.scan(firmware_file, min_length=min_string_len)

    # 4. Binwalk
    if no_binwalk:
        log("Skipping binwalk (--no-binwalk)")
        binwalk_result: dict = {"findings": [], "extracted": [], "error": "skipped"}
    elif extract:
        out_dir = extract_dir or firmware_file.parent / f"{firmware_file.stem}_extracted"
        log(f"Running binwalk extraction → {out_dir}")
        binwalk_result = binwalk_runner.extract(firmware_file, out_dir)
    else:
        log("Running binwalk scan...")
        binwalk_result = binwalk_runner.scan(firmware_file)

    if binwalk_result.get("error") and binwalk_result["error"] != "skipped":
        click.echo(f"[!] Binwalk: {binwalk_result['error']}", err=True)

    # 5. YARA
    rules_path = rules or DEFAULT_RULES
    log(f"Running YARA scan ({rules_path.name})...")
    yara_result = yara_runner.scan(firmware_file, rules_path=rules_path)

    if yara_result.get("error"):
        click.echo(f"[!] YARA: {yara_result['error']}", err=True)

    # 6. ELF structure / hardening analysis (no-op for non-ELF files)
    log("Analyzing ELF structure...")
    elf_result = elf_analysis.analyze(firmware_file)
    if elf_result.get("is_elf") and elf_result.get("error"):
        click.echo(f"[!] ELF: {elf_result['error']}", err=True)

    # 7. Risk scoring
    log("Computing risk score...")
    risk_result = risk_scoring.score(
        entropy_result, strings_result, yara_result, binwalk_result, elf_result
    )

    # 8. Report
    full_report = report.build(
        firmware_file,
        hash_result,
        entropy_result,
        strings_result,
        binwalk_result,
        yara_result,
        risk_result,
        elf_result,
    )

    if output:
        report.write(full_report, output)
        log(f"Report saved to: {output}")
    else:
        report.print_summary(full_report)


if __name__ == "__main__":
    main()
