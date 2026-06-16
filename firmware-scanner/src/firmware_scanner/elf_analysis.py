"""Faz 2 — ELF binary structure and security-mitigation analysis.

Parses ELF headers, sections, segments, dynamic symbols, and the classic
hardening flags (PIE / NX / RELRO / stack canary / stripped) that matter
for firmware triage. Never executes the analyzed file.
"""
from __future__ import annotations

from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

    _ELFTOOLS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dependency missing
    _ELFTOOLS_AVAILABLE = False

PF_X = 0x1  # ELF segment "execute" flag
DF_BIND_NOW = 0x8  # DT_FLAGS bit indicating BIND_NOW


def is_elf(path: Path) -> bool:
    """Check the first 4 bytes for the ELF magic number."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def analyze(path: Path) -> dict:
    """Parse ELF structure and security mitigations.

    Returns:
        {"is_elf": False} for non-ELF files.
        {"is_elf": True, "error": str, ...} with error set (and other
        fields empty/default) if pyelftools is missing or parsing fails.
        Otherwise the full structural breakdown.
    """
    if not is_elf(path):
        return {"is_elf": False}

    if not _ELFTOOLS_AVAILABLE:
        return {"is_elf": True, "error": "pyelftools not installed"}

    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)

            header = _parse_header(elf)
            segments = _parse_segments(elf)
            sections = _parse_sections(elf)
            shared_libs, imported, exported = _parse_dynamic_symbols(elf)
            security = _parse_security(elf, segments)
            security["stripped"] = elf.get_section_by_name(".symtab") is None

        return {
            "is_elf": True,
            "error": None,
            "header": header,
            "segments": segments,
            "sections": sections,
            "shared_libraries": shared_libs,
            "imported_symbols": imported,
            "exported_symbols": exported,
            "security": security,
        }
    except Exception as exc:  # noqa: BLE001 - never let a malformed ELF crash the scan
        return {"is_elf": True, "error": f"Failed to parse ELF: {exc}"}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_header(elf: "ELFFile") -> dict:
    h = elf.header
    return {
        "class": f"ELF{elf.elfclass}",
        "endianness": "little" if elf.little_endian else "big",
        "type": h["e_type"],
        "machine": elf.get_machine_arch(),
        "entry_point": hex(h["e_entry"]),
        "osabi": h["e_ident"]["EI_OSABI"],
    }


def _parse_segments(elf: "ELFFile") -> list[dict]:
    return [
        {
            "type": seg["p_type"],
            "flags": seg["p_flags"],
            "vaddr": hex(seg["p_vaddr"]),
            "filesz": seg["p_filesz"],
            "memsz": seg["p_memsz"],
        }
        for seg in elf.iter_segments()
    ]


def _parse_sections(elf: "ELFFile") -> list[dict]:
    return [
        {
            "name": sec.name,
            "type": sec["sh_type"],
            "address": hex(sec["sh_addr"]),
            "size": sec["sh_size"],
        }
        for sec in elf.iter_sections()
    ]


def _parse_dynamic_symbols(elf: "ELFFile") -> tuple[list[str], list[str], list[str]]:
    shared_libs: list[str] = []
    imported: set[str] = set()
    exported: set[str] = set()

    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    shared_libs.append(tag.needed)

        if isinstance(section, SymbolTableSection) and section.name == ".dynsym":
            for sym in section.iter_symbols():
                if not sym.name:
                    continue
                if sym["st_shndx"] == "SHN_UNDEF":
                    imported.add(sym.name)
                else:
                    exported.add(sym.name)

    return shared_libs, sorted(imported), sorted(exported)


def _parse_security(elf: "ELFFile", segments: list[dict]) -> dict:
    has_interp = any(s["type"] == "PT_INTERP" for s in segments)
    pie = elf.header["e_type"] == "ET_DYN" and has_interp

    gnu_stack = next((s for s in segments if s["type"] == "PT_GNU_STACK"), None)
    nx = bool(gnu_stack is not None and not (gnu_stack["flags"] & PF_X))

    has_relro_segment = any(s["type"] == "PT_GNU_RELRO" for s in segments)
    bind_now = False
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    bind_now = True
                elif tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & DF_BIND_NOW:
                    bind_now = True

    if has_relro_segment and bind_now:
        relro = "full"
    elif has_relro_segment:
        relro = "partial"
    else:
        relro = "none"

    return {"pie": pie, "nx": nx, "relro": relro}
