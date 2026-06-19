"""Tests for Feature 4: professional PDF report upgrade."""
from __future__ import annotations

import pytest

# ── availability check ────────────────────────────────────────────────────────

def _xhtml2pdf_available() -> bool:
    try:
        import xhtml2pdf  # noqa: F401
        return True
    except ImportError:
        return False


requires_xhtml2pdf = pytest.mark.skipif(
    not _xhtml2pdf_available(), reason="xhtml2pdf not installed"
)


# ── fixture helpers ───────────────────────────────────────────────────────────

def _minimal_report(**overrides) -> dict:
    base = {
        "scan_id": "test-scan-001",
        "file": {
            "name": "test_firmware.bin",
            "size": {"bytes": 65536, "human": "64.0 KB"},
            "type": "application/octet-stream",
            "hashes": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32},
        },
        "entropy": {"overall": 4.5, "interpretation": "mixed content"},
        "strings": {"suspicious": [], "suspicious_count": 0, "total": 100, "category_counts": {}},
        "yara": {"matches": [], "error": None},
        "binwalk": {"findings": [], "error": None},
        "elf": {"is_elf": False},
        "checksec": {"is_elf": False},
        "arch": {"is_bare_metal": False},
        "crypto": {"matches": [], "count": 0},
        "components": {"components": [], "count": 0},
        "certs": {"certificates": [], "count": 0},
        "risk": {"score": 0, "level": "informational", "reasons": []},
    }
    base.update(overrides)
    return base


# ── module structure ──────────────────────────────────────────────────────────

def test_pdf_report_importable():
    from api import pdf_report  # noqa: F401
    assert hasattr(pdf_report, "render_pdf")


def test_render_pdf_function_signature():
    from api.pdf_report import render_pdf
    import inspect
    sig = inspect.signature(render_pdf)
    assert "report" in sig.parameters
    assert "scan_meta" in sig.parameters


# ── helper functions ──────────────────────────────────────────────────────────

def test_yara_by_severity_sorts_critical_first():
    from api.pdf_report import _yara_by_severity
    yara = {"matches": [
        {"rule": "LowRule",  "severity": "low"},
        {"rule": "CritRule", "severity": "critical"},
        {"rule": "HighRule", "severity": "high"},
    ]}
    result = _yara_by_severity(yara)
    assert result[0]["rule"] == "CritRule"
    assert result[1]["rule"] == "HighRule"
    assert result[2]["rule"] == "LowRule"


def test_strings_by_severity_sorts_private_key_first():
    from api.pdf_report import _strings_by_severity
    strings = {"suspicious": [
        {"category": "URL",         "value": "http://x", "offset": 0, "encoding": "ascii"},
        {"category": "PRIVATE_KEY", "value": "---BEGIN", "offset": 100, "encoding": "ascii"},
        {"category": "CREDENTIAL",  "value": "admin123", "offset": 50, "encoding": "ascii"},
    ]}
    result = _strings_by_severity(strings)
    assert result[0]["category"] == "PRIVATE_KEY"
    assert result[1]["category"] == "CREDENTIAL"
    assert result[2]["category"] == "URL"


def test_exec_summary_bullets_informational():
    from api.pdf_report import _exec_summary_bullets
    report = _minimal_report()
    bullets = _exec_summary_bullets(report)
    assert isinstance(bullets, list)
    assert len(bullets) >= 1
    assert "informational" in bullets[0].lower()


def test_exec_summary_bullets_with_findings():
    from api.pdf_report import _exec_summary_bullets
    report = _minimal_report(
        yara={"matches": [{"rule": "X", "severity": "high"}], "error": None},
        strings={"suspicious": [], "suspicious_count": 5, "total": 100, "category_counts": {}},
        risk={"score": 60, "level": "high", "reasons": []},
    )
    bullets = _exec_summary_bullets(report)
    text = " ".join(bullets)
    assert "1 yara" in text.lower()
    assert "5 suspicious" in text.lower()


def test_exec_summary_bullets_high_entropy():
    from api.pdf_report import _exec_summary_bullets
    report = _minimal_report(entropy={"overall": 7.9, "interpretation": "encrypted"})
    bullets = _exec_summary_bullets(report)
    assert any("entropy" in b.lower() for b in bullets)


def test_exec_summary_bullets_elf_hardening_gaps():
    from api.pdf_report import _exec_summary_bullets
    report = _minimal_report(elf={
        "is_elf": True,
        "security": {"nx": False, "pie": True, "relro": "none", "stripped": True},
    })
    bullets = _exec_summary_bullets(report)
    assert any("NX" in b or "RELRO" in b for b in bullets)


# ── PDF generation ────────────────────────────────────────────────────────────

@requires_xhtml2pdf
def test_render_pdf_returns_bytes():
    from api.pdf_report import render_pdf
    pdf_bytes = render_pdf(_minimal_report())
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100


@requires_xhtml2pdf
def test_render_pdf_starts_with_pdf_header():
    from api.pdf_report import render_pdf
    pdf_bytes = render_pdf(_minimal_report())
    assert pdf_bytes.startswith(b"%PDF"), "Output is not a valid PDF (missing %PDF header)"


@requires_xhtml2pdf
def test_render_pdf_with_yara_matches():
    from api.pdf_report import render_pdf
    report = _minimal_report(
        yara={"matches": [
            {"rule": "EmbeddedRSAPrivateKey", "severity": "critical", "strings": []},
            {"rule": "HardcodedDefaultCredentials", "severity": "high", "strings": []},
        ], "error": None},
        risk={"score": 80, "level": "critical", "reasons": ["YARA: EmbeddedRSAPrivateKey"]},
    )
    pdf_bytes = render_pdf(report, {"created_at": "2026-01-01 10:00 UTC"})
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_with_suspicious_strings():
    from api.pdf_report import render_pdf
    report = _minimal_report(
        strings={
            "total": 200,
            "suspicious_count": 2,
            "category_counts": {"CREDENTIAL": 1, "URL": 1},
            "suspicious": [
                {"category": "CREDENTIAL", "value": "admin:admin", "offset": 100, "encoding": "ascii"},
                {"category": "URL", "value": "http://example.com", "offset": 200, "encoding": "ascii"},
            ],
        }
    )
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_with_compliance_section():
    from api.pdf_report import render_pdf
    from firmware_scanner import compliance
    report = _minimal_report(
        yara={"matches": [{"rule": "HardcodedDefaultCredentials", "severity": "high", "strings": []}], "error": None},
        risk={"score": 30, "level": "medium", "reasons": []},
    )
    report["compliance"] = compliance.analyze(report)
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_with_sbom():
    from api.pdf_report import render_pdf
    report = _minimal_report(
        components={
            "count": 2,
            "components": [
                {"component": "openssl", "version": "1.0.2k", "evidence_offset": 100, "evidence": "openssl"},
                {"component": "curl", "version": "7.64.0", "evidence_offset": 200, "evidence": "libcurl"},
            ],
        }
    )
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_with_elf_data():
    from api.pdf_report import render_pdf
    report = _minimal_report(
        elf={
            "is_elf": True,
            "header": {
                "machine": "x86_64", "class": "ELF64", "endianness": "little",
                "type": "ET_EXEC", "entry_point": "0x400000",
            },
            "security": {"nx": True, "pie": False, "relro": "partial", "stripped": False},
            "shared_libraries": ["libc.so.6"],
            "imported_symbols": [], "exported_symbols": [],
        }
    )
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_with_crypto_constants():
    from api.pdf_report import render_pdf
    report = _minimal_report(
        crypto={
            "count": 1,
            "matches": [{"algo": "AES-128", "offset": 512, "confidence": "high"}],
        }
    )
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")


@requires_xhtml2pdf
def test_render_pdf_all_risk_levels():
    from api.pdf_report import render_pdf
    for level in ("informational", "low", "medium", "high", "critical"):
        report = _minimal_report(risk={"score": 50, "level": level, "reasons": []})
        pdf_bytes = render_pdf(report)
        assert pdf_bytes.startswith(b"%PDF"), f"Failed for risk level: {level}"


@requires_xhtml2pdf
def test_render_pdf_with_scan_meta():
    from api.pdf_report import render_pdf
    scan_meta = {
        "created_at": "2026-01-15 09:30 UTC",
        "completed_at": "2026-01-15 09:31 UTC",
        "filename": "device_v2.3.bin",
    }
    pdf_bytes = render_pdf(_minimal_report(), scan_meta)
    assert pdf_bytes.startswith(b"%PDF")
