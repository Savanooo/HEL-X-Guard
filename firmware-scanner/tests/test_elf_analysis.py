"""Tests for elf_analysis.py — synthetic ELF64 binaries built byte-by-byte.

We hand-craft minimal-but-valid ELF64 little-endian files with struct.pack
so the test suite never depends on a real compiled Linux binary (this repo
is developed on Windows, where no native ELF toolchain is available).
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from firmware_scanner import elf_analysis

# ── ELF constant values ──────────────────────────────────────────────────────

ET_EXEC = 2
ET_DYN = 3
EM_ARM = 40

PT_LOAD = 1
PT_INTERP = 3
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

DT_NULL = 0
DT_NEEDED = 1

EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
SYM_SIZE = 24
DYN_SIZE = 16


# ── Minimal ELF64 builder ─────────────────────────────────────────────────────

def _ehdr(
    *, e_type: int, e_machine: int, e_entry: int, e_phoff: int, e_shoff: int,
    e_phnum: int, e_shnum: int, e_shstrndx: int,
) -> bytes:
    return struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0, 0,          # magic, CLASS64, DATA2LSB, VERSION, OSABI, ABIVERSION
        e_type, e_machine, 1,                # e_type, e_machine, e_version
        e_entry, e_phoff, e_shoff,
        0,                                    # e_flags
        EHDR_SIZE, PHDR_SIZE if e_phnum else 0, e_phnum,
        SHDR_SIZE if e_shnum else 0, e_shnum, e_shstrndx,
    )


def _phdr(*, p_type: int, p_flags: int, p_offset: int = 0, p_filesz: int = 0, p_memsz: int = 0) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        p_type, p_flags, p_offset, 0, 0, p_filesz, p_memsz, 0,
    )


def _shdr(
    *, sh_name: int, sh_type: int, sh_offset: int, sh_size: int,
    sh_link: int = 0, sh_info: int = 0, sh_entsize: int = 0,
) -> bytes:
    return struct.pack(
        "<IIQQQQIIQQ",
        sh_name, sh_type, 0, 0, sh_offset, sh_size, sh_link, sh_info, 1, sh_entsize,
    )


def _sym(*, st_name: int, bind: int, typ: int, shndx: int) -> bytes:
    info = (bind << 4) | typ
    return struct.pack("<IBBHQQ", st_name, info, 0, shndx, 0, 0)


def _dyn(*, d_tag: int, d_val: int) -> bytes:
    return struct.pack("<qQ", d_tag, d_val)


def _header_only_elf(e_type: int = ET_EXEC, e_machine: int = EM_ARM) -> bytes:
    """64-byte ELF header, no program/section headers."""
    return _ehdr(
        e_type=e_type, e_machine=e_machine, e_entry=0x8000,
        e_phoff=0, e_shoff=0, e_phnum=0, e_shnum=0, e_shstrndx=0,
    )


def _elf_with_segments(*, e_type: int, segments: list[bytes]) -> bytes:
    """Header + program headers, no sections."""
    phoff = EHDR_SIZE
    header = _ehdr(
        e_type=e_type, e_machine=EM_ARM, e_entry=0x8000,
        e_phoff=phoff, e_shoff=0, e_phnum=len(segments), e_shnum=0, e_shstrndx=0,
    )
    return header + b"".join(segments)


def _full_featured_elf() -> bytes:
    """ELF with segments (PT_LOAD + non-executable PT_GNU_STACK) and sections
    (.shstrtab, .dynstr, .dynsym, .dynamic, .symtab) to exercise every code path."""
    phdrs = [
        _phdr(p_type=PT_LOAD, p_flags=PF_R | PF_X),
        _phdr(p_type=PT_GNU_STACK, p_flags=PF_R | PF_W),  # no PF_X -> NX enabled
    ]
    phdr_bytes = b"".join(phdrs)
    phoff = EHDR_SIZE
    content_start = phoff + len(phdr_bytes)

    # .shstrtab content
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00.symtab\x00"
    off_shstrtab_name = 1
    off_dynstr_name = 11
    off_dynsym_name = 19
    off_dynamic_name = 27
    off_symtab_name = 36

    # .dynstr content (symbol + library names)
    dynstr = b"\x00printf\x00memcpy\x00libc.so.6\x00"
    off_printf = 1
    off_memcpy = 8
    off_libc = 15

    # .dynsym: null symbol + printf (undefined/imported) + memcpy (defined/exported)
    dynsym = (
        _sym(st_name=0, bind=0, typ=0, shndx=0)            # mandatory null entry
        + _sym(st_name=off_printf, bind=1, typ=2, shndx=0)  # SHN_UNDEF -> imported
        + _sym(st_name=off_memcpy, bind=1, typ=2, shndx=1)  # defined -> exported
    )

    # .dynamic: one DT_NEEDED + terminator
    dynamic = _dyn(d_tag=DT_NEEDED, d_val=off_libc) + _dyn(d_tag=DT_NULL, d_val=0)

    symtab = b""  # presence of the section (even empty) marks "not stripped"

    sections_content = shstrtab + dynstr + dynsym + dynamic + symtab
    off_shstrtab = content_start
    off_dynstr = off_shstrtab + len(shstrtab)
    off_dynsym = off_dynstr + len(dynstr)
    off_dynamic = off_dynsym + len(dynsym)
    off_symtab = off_dynamic + len(dynamic)

    shdrs = [
        _shdr(sh_name=0, sh_type=SHT_NULL, sh_offset=0, sh_size=0),
        _shdr(sh_name=off_shstrtab_name, sh_type=SHT_STRTAB, sh_offset=off_shstrtab, sh_size=len(shstrtab)),
        _shdr(sh_name=off_dynstr_name, sh_type=SHT_STRTAB, sh_offset=off_dynstr, sh_size=len(dynstr)),
        _shdr(
            sh_name=off_dynsym_name, sh_type=SHT_DYNSYM, sh_offset=off_dynsym, sh_size=len(dynsym),
            sh_link=2, sh_info=1, sh_entsize=SYM_SIZE,
        ),
        _shdr(
            sh_name=off_dynamic_name, sh_type=SHT_DYNAMIC, sh_offset=off_dynamic, sh_size=len(dynamic),
            sh_link=2, sh_entsize=DYN_SIZE,
        ),
        _shdr(sh_name=off_symtab_name, sh_type=SHT_SYMTAB, sh_offset=off_symtab, sh_size=0, sh_link=2, sh_entsize=SYM_SIZE),
    ]
    shdr_bytes = b"".join(shdrs)
    shoff = content_start + len(sections_content)

    header = _ehdr(
        e_type=ET_EXEC, e_machine=EM_ARM, e_entry=0x8000,
        e_phoff=phoff, e_shoff=shoff,
        e_phnum=len(phdrs), e_shnum=len(shdrs), e_shstrndx=1,
    )

    return header + phdr_bytes + sections_content + shdr_bytes


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def header_only_elf(tmp_path: Path) -> Path:
    p = tmp_path / "header_only.elf"
    p.write_bytes(_header_only_elf())
    return p


@pytest.fixture
def full_featured_elf(tmp_path: Path) -> Path:
    p = tmp_path / "full.elf"
    p.write_bytes(_full_featured_elf())
    return p


# ── is_elf() ──────────────────────────────────────────────────────────────────

def test_is_elf_true_on_magic(tmp_path):
    p = tmp_path / "magic.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert elf_analysis.is_elf(p)


def test_is_elf_false_on_non_elf(tmp_path):
    p = tmp_path / "not_elf.bin"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
    assert not elf_analysis.is_elf(p)


def test_is_elf_false_on_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert not elf_analysis.is_elf(p)


# ── analyze(): non-ELF passthrough ───────────────────────────────────────────

def test_analyze_non_elf_returns_false(tmp_path):
    p = tmp_path / "plain.txt"
    p.write_bytes(b"just some text, not a binary at all")
    result = elf_analysis.analyze(p)
    assert result == {"is_elf": False}


def test_analyze_corrupt_elf_returns_error_not_exception(tmp_path):
    """Valid magic but truncated header must not raise."""
    p = tmp_path / "corrupt.elf"
    p.write_bytes(b"\x7fELF" + b"\x02\x01\x01\x00\x00" + b"\x00" * 5)  # far too short
    result = elf_analysis.analyze(p)
    assert result["is_elf"] is True
    assert result["error"] is not None


# ── analyze(): header-only ELF ───────────────────────────────────────────────

def test_header_only_fields(header_only_elf):
    result = elf_analysis.analyze(header_only_elf)
    assert result["is_elf"] is True
    assert result["error"] is None
    h = result["header"]
    assert h["class"] == "ELF64"
    assert h["endianness"] == "little"
    assert h["type"] == "ET_EXEC"
    assert h["machine"] == "ARM"
    assert h["entry_point"] == "0x8000"


def test_header_only_no_sections_or_segments(header_only_elf):
    result = elf_analysis.analyze(header_only_elf)
    assert result["sections"] == []
    assert result["segments"] == []
    assert result["shared_libraries"] == []
    assert result["imported_symbols"] == []
    assert result["exported_symbols"] == []


def test_header_only_is_stripped(header_only_elf):
    """No .symtab section at all -> reported as stripped."""
    result = elf_analysis.analyze(header_only_elf)
    assert result["security"]["stripped"] is True


def test_header_only_nx_false_when_no_gnu_stack(header_only_elf):
    """Absence of PT_GNU_STACK is treated as NX-disabled (checksec convention)."""
    result = elf_analysis.analyze(header_only_elf)
    assert result["security"]["nx"] is False


# ── analyze(): PIE detection ─────────────────────────────────────────────────

def test_pie_true_for_dyn_with_interp(tmp_path):
    data = _elf_with_segments(
        e_type=ET_DYN,
        segments=[_phdr(p_type=PT_INTERP, p_flags=PF_R)],
    )
    p = tmp_path / "pie.elf"
    p.write_bytes(data)
    result = elf_analysis.analyze(p)
    assert result["security"]["pie"] is True


def test_pie_false_for_exec_type(tmp_path):
    data = _elf_with_segments(
        e_type=ET_EXEC,
        segments=[_phdr(p_type=PT_LOAD, p_flags=PF_R | PF_X)],
    )
    p = tmp_path / "noexec_pie.elf"
    p.write_bytes(data)
    result = elf_analysis.analyze(p)
    assert result["security"]["pie"] is False


def test_pie_false_for_dyn_without_interp(tmp_path):
    """ET_DYN without PT_INTERP is a shared library, not a PIE executable."""
    data = _elf_with_segments(
        e_type=ET_DYN,
        segments=[_phdr(p_type=PT_LOAD, p_flags=PF_R | PF_X)],
    )
    p = tmp_path / "shared_lib.elf"
    p.write_bytes(data)
    result = elf_analysis.analyze(p)
    assert result["security"]["pie"] is False


# ── analyze(): NX detection ──────────────────────────────────────────────────

def test_nx_false_when_gnu_stack_executable(tmp_path):
    data = _elf_with_segments(
        e_type=ET_EXEC,
        segments=[_phdr(p_type=PT_GNU_STACK, p_flags=PF_R | PF_W | PF_X)],
    )
    p = tmp_path / "exec_stack.elf"
    p.write_bytes(data)
    result = elf_analysis.analyze(p)
    assert result["security"]["nx"] is False


def test_nx_true_when_gnu_stack_not_executable(tmp_path):
    data = _elf_with_segments(
        e_type=ET_EXEC,
        segments=[_phdr(p_type=PT_GNU_STACK, p_flags=PF_R | PF_W)],
    )
    p = tmp_path / "noexec_stack.elf"
    p.write_bytes(data)
    result = elf_analysis.analyze(p)
    assert result["security"]["nx"] is True


# ── analyze(): full-featured ELF ─────────────────────────────────────────────

def test_full_featured_header(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    assert result["error"] is None
    assert result["header"]["type"] == "ET_EXEC"
    assert result["header"]["machine"] == "ARM"


def test_full_featured_sections_present(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    names = {s["name"] for s in result["sections"]}
    assert {".shstrtab", ".dynstr", ".dynsym", ".dynamic", ".symtab"} <= names


def test_full_featured_segments_present(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    types = {s["type"] for s in result["segments"]}
    assert "PT_LOAD" in types
    assert "PT_GNU_STACK" in types


def test_full_featured_shared_libraries(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    assert result["shared_libraries"] == ["libc.so.6"]


def test_full_featured_imported_symbols(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    assert "printf" in result["imported_symbols"]
    assert "printf" not in result["exported_symbols"]


def test_full_featured_exported_symbols(full_featured_elf):
    result = elf_analysis.analyze(full_featured_elf)
    assert "memcpy" in result["exported_symbols"]
    assert "memcpy" not in result["imported_symbols"]


def test_full_featured_not_stripped(full_featured_elf):
    """.symtab section is present -> not stripped."""
    result = elf_analysis.analyze(full_featured_elf)
    assert result["security"]["stripped"] is False


def test_full_featured_nx_enabled(full_featured_elf):
    """PT_GNU_STACK present without PF_X -> NX enabled."""
    result = elf_analysis.analyze(full_featured_elf)
    assert result["security"]["nx"] is True


def test_full_featured_no_relro(full_featured_elf):
    """No PT_GNU_RELRO segment -> relro = none."""
    result = elf_analysis.analyze(full_featured_elf)
    assert result["security"]["relro"] == "none"
