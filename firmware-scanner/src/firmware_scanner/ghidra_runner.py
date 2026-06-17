"""Optional, heavy — Ghidra headless decompilation wrapper.

Ghidra statically disassembles/decompiles the firmware binary; the binary
itself is NEVER executed. This module only runs if GHIDRA_HOME points to a
valid Ghidra installation; otherwise every call degrades gracefully and
reports unavailability instead of raising.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

DEFAULT_TIMEOUT = 600  # seconds — full headless analysis can be slow

_EXPORT_SCRIPT = '''import json, traceback, os

out_path = os.environ.get("HELIX_GHIDRA_OUTPUT", "")
if not out_path:
    raise RuntimeError("HELIX_GHIDRA_OUTPUT env var not set")

out = {"functions": [], "error": None}
try:
    from ghidra.app.decompiler import DecompInterface
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    results = []
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        res = decompiler.decompileFunction(func, 30, monitor)
        if res.decompileCompleted():
            results.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "code": res.getDecompiledFunction().getC(),
            })
    decompiler.dispose()
    out = {"functions": results, "error": None}
except Exception as e:
    out = {"functions": [], "error": traceback.format_exc()}
finally:
    with open(out_path, "w") as f:
        f.write(json.dumps(out))
'''


def _analyzer_path(ghidra_home: Path) -> Path:
    script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    return ghidra_home / "support" / script_name


def is_available() -> bool:
    """True if GHIDRA_HOME is set and points at a real Ghidra install."""
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if not ghidra_home:
        return False
    return _analyzer_path(Path(ghidra_home)).exists()


def decompile(path: Path, output_dir: Path, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run Ghidra headless analysis and return decompiled pseudocode per function.

    Never raises. Returns {"available": False, ...} when Ghidra is not
    configured, or {"available": True, "error": str, ...} on any failure.

    Returns:
        {"available": bool, "error": str | None, "functions": list[dict]}
    """
    if not is_available():
        return {
            "available": False,
            "error": "Ghidra not configured. Set GHIDRA_HOME to enable decompilation.",
            "functions": [],
        }

    ghidra_home = Path(os.environ["GHIDRA_HOME"])
    analyzer = _analyzer_path(ghidra_home)

    output_dir.mkdir(parents=True, exist_ok=True)
    result_json = output_dir / "decompiled.json"

    with tempfile.TemporaryDirectory() as tmp:
        script_path = Path(tmp) / "ExportDecompiled.py"
        script_path.write_text(_EXPORT_SCRIPT, encoding="utf-8")

        project_dir = Path(tmp) / "project"
        project_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(analyzer), str(project_dir), "helix_project",
            "-import", str(path),
            "-scriptPath", tmp,
            "-postScript", "ExportDecompiled.py",
            "-deleteProject",
        ]

        run_env = {**os.environ, "HELIX_GHIDRA_OUTPUT": str(result_json)}

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=run_env)
        except subprocess.TimeoutExpired:
            return {"available": True, "error": f"Ghidra timed out after {timeout}s", "functions": []}
        except Exception as exc:  # noqa: BLE001
            return {"available": True, "error": f"Ghidra execution failed: {exc}", "functions": []}

        if proc.returncode != 0:
            combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            detail = combined[-3000:]
            return {
                "available": True,
                "error": f"Ghidra exited with code {proc.returncode}: {detail}",
                "functions": [],
            }

        if not result_json.exists():
            return {"available": True, "error": "Ghidra produced no output file", "functions": []}

        try:
            data = json.loads(result_json.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return {"available": True, "error": f"Failed to parse Ghidra output: {exc}", "functions": []}

        if isinstance(data, list):
            functions, script_error = data, None
        else:
            functions = data.get("functions", [])
            script_error = data.get("error")

        if script_error:
            return {"available": True, "error": f"Ghidra script error: {script_error}", "functions": functions}

    return {"available": True, "error": None, "functions": functions}
