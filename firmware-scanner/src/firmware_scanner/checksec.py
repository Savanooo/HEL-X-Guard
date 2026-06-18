"""ELF security mitigation checker using lief.

Reports: NX (non-executable stack), PIE, RELRO (none/partial/full),
stack canary, FORTIFY_SOURCE, RPATH/RUNPATH presence.

Only meaningful for ELF inputs — returns {is_elf: False} for raw binaries.
"""
from __future__ import annotations

from pathlib import Path


def analyze(path: Path) -> dict:
    """Parse ELF hardening properties.

    Returns:
        {
            is_elf: bool,
            nx: bool,           # GNU_STACK segment not executable
            pie: bool,          # ET_DYN file type
            relro: str,         # "none" | "partial" | "full"
            canary: bool,       # __stack_chk_fail imported
            fortify: bool,      # *_chk symbols present
            rpath: str | None,
            runpath: str | None,
            error: str | None,
        }
    """
    try:
        import lief  # optional dependency
    except ImportError:
        return {
            "is_elf": False,
            "error": "lief not installed — install with: pip install lief",
        }

    try:
        binary = lief.parse(str(path))
    except Exception as exc:  # noqa: BLE001
        return {"is_elf": False, "error": f"lief parse error: {exc}"}

    if binary is None:
        return {"is_elf": False, "error": None}

    # lief >= 0.13 uses lief.ELF.Binary; older versions also work
    if not isinstance(binary, lief.ELF.Binary):
        return {"is_elf": False, "error": None}

    try:
        # ── NX ────────────────────────────────────────────────────────────────
        nx = True  # default assume NX; only False if GNU_STACK is executable
        for seg in binary.segments:
            try:
                is_gnu_stack = (
                    seg.type == lief.ELF.Segment.TYPE.GNU_STACK
                    or str(seg.type) in ("GNU_STACK", "PT_GNU_STACK")
                )
            except Exception:
                is_gnu_stack = False
            if is_gnu_stack:
                try:
                    nx = not bool(seg.flags & lief.ELF.Segment.FLAGS.X)
                except Exception:
                    nx = not bool(int(seg.flags) & 0x1)
                break

        # ── PIE ───────────────────────────────────────────────────────────────
        try:
            pie = (
                binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
                or str(binary.header.file_type) in ("DYN", "ET_DYN")
            )
        except Exception:
            pie = False

        # ── RELRO ─────────────────────────────────────────────────────────────
        has_relro_seg = False
        for seg in binary.segments:
            try:
                if (
                    seg.type == lief.ELF.Segment.TYPE.GNU_RELRO
                    or str(seg.type) in ("GNU_RELRO", "PT_GNU_RELRO")
                ):
                    has_relro_seg = True
                    break
            except Exception:
                pass

        bind_now = False
        try:
            for entry in binary.dynamic_entries:
                tag_str = str(entry.tag)
                if "BIND_NOW" in tag_str:
                    bind_now = True
                    break
                if "FLAGS" in tag_str and not "FLAGS_1" in tag_str:
                    try:
                        if int(entry.value) & 0x8:  # DF_BIND_NOW
                            bind_now = True
                    except Exception:
                        pass
                if "FLAGS_1" in tag_str:
                    try:
                        if int(entry.value) & 0x1:  # DF_1_NOW
                            bind_now = True
                    except Exception:
                        pass
        except Exception:
            pass

        if has_relro_seg:
            relro = "full" if bind_now else "partial"
        else:
            relro = "none"

        # ── Stack canary ──────────────────────────────────────────────────────
        canary = False
        try:
            for sym in binary.symbols:
                name = sym.name or ""
                if "__stack_chk_fail" in name:
                    canary = True
                    break
        except Exception:
            pass

        # ── FORTIFY ───────────────────────────────────────────────────────────
        fortify = False
        try:
            for sym in binary.symbols:
                name = sym.name or ""
                if name.endswith("_chk") or "_chk@" in name:
                    fortify = True
                    break
        except Exception:
            pass

        # ── RPATH / RUNPATH ───────────────────────────────────────────────────
        rpath: str | None = None
        runpath: str | None = None
        try:
            for entry in binary.dynamic_entries:
                tag_str = str(entry.tag)
                if "RPATH" in tag_str and "RUNPATH" not in tag_str:
                    try:
                        rpath = entry.name
                    except Exception:
                        rpath = str(entry.value)
                elif "RUNPATH" in tag_str:
                    try:
                        runpath = entry.name
                    except Exception:
                        runpath = str(entry.value)
        except Exception:
            pass

        return {
            "is_elf":  True,
            "nx":      nx,
            "pie":     pie,
            "relro":   relro,
            "canary":  canary,
            "fortify": fortify,
            "rpath":   rpath,
            "runpath": runpath,
            "error":   None,
        }

    except Exception as exc:  # noqa: BLE001
        return {"is_elf": False, "error": str(exc)}
