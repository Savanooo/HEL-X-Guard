"""Tests for sandbox.py — Docker calls are mocked; no real container needed."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from firmware_scanner import sandbox


# ── Helpers ───────────────────────────────────────────────────────────────────

_FAKE_REPORT = {
    "scan_id": "00000000-0000-0000-0000-000000000001",
    "risk": {"score": 42, "level": "medium", "reasons": ["test"]},
}


def _mock_docker_run_ok(output_dir: Path):
    """Return a mock subprocess.run that writes a report and exits 0."""
    def _run(cmd, **kwargs):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "report.json").write_text(json.dumps(_FAKE_REPORT))
        return MagicMock(returncode=0, stderr="", stdout="")
    return _run


# ── DockerNotFoundError ───────────────────────────────────────────────────────

def test_docker_not_found_raises(synthetic_firmware_file, tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(sandbox.DockerNotFoundError):
            sandbox.run_in_docker(synthetic_firmware_file, tmp_path / "out")


def test_docker_exe_raises_when_missing():
    with patch("shutil.which", return_value=None):
        with pytest.raises(sandbox.DockerNotFoundError):
            sandbox._docker_exe()


# ── _image_exists ─────────────────────────────────────────────────────────────

def test_image_exists_true_on_zero_exit():
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        assert sandbox._image_exists("/usr/bin/docker", "helix-guard-scanner:latest")


def test_image_exists_false_on_nonzero_exit():
    with patch("subprocess.run", return_value=MagicMock(returncode=1)):
        assert not sandbox._image_exists("/usr/bin/docker", "missing:latest")


# ── run_in_docker ─────────────────────────────────────────────────────────────

def test_run_returns_parsed_report(synthetic_firmware_file, tmp_path):
    out_dir = tmp_path / "output"

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch("subprocess.run", side_effect=_mock_docker_run_ok(out_dir)):
                result = sandbox.run_in_docker(synthetic_firmware_file, out_dir)

    assert result["scan_id"] == _FAKE_REPORT["scan_id"]
    assert result["risk"]["score"] == 42


def test_run_creates_output_dir(synthetic_firmware_file, tmp_path):
    out_dir = tmp_path / "new" / "nested" / "output"
    assert not out_dir.exists()

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch("subprocess.run", side_effect=_mock_docker_run_ok(out_dir)):
                sandbox.run_in_docker(synthetic_firmware_file, out_dir)

    assert out_dir.exists()


def test_nonzero_exit_raises_sandbox_error(synthetic_firmware_file, tmp_path):
    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="boom")):
                with pytest.raises(sandbox.SandboxError, match="exit"):
                    sandbox.run_in_docker(synthetic_firmware_file, tmp_path / "out")


def test_timeout_raises_sandbox_error(synthetic_firmware_file, tmp_path):
    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=1),
            ):
                with pytest.raises(sandbox.SandboxError, match="timed out"):
                    sandbox.run_in_docker(
                        synthetic_firmware_file, tmp_path / "out", timeout=1
                    )


def test_missing_image_no_auto_build_raises(synthetic_firmware_file, tmp_path):
    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=False):
            with pytest.raises(sandbox.DockerImageNotFoundError):
                sandbox.run_in_docker(
                    synthetic_firmware_file,
                    tmp_path / "out",
                    auto_build=False,
                )


# ── Security flags in docker run command ──────────────────────────────────────

def test_docker_run_cmd_has_all_security_flags(synthetic_firmware_file, tmp_path):
    """The docker run command must include every required security constraint."""
    out_dir = tmp_path / "out"
    captured: list[list[str]] = []

    def capture(cmd, **kwargs):
        captured.append(list(cmd))
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.json").write_text(json.dumps(_FAKE_REPORT))
        return MagicMock(returncode=0, stderr="")

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch("subprocess.run", side_effect=capture):
                sandbox.run_in_docker(synthetic_firmware_file, out_dir)

    assert captured, "subprocess.run was never called"
    cmd = captured[0]
    cmd_str = " ".join(cmd)

    assert "--network" in cmd and "none" in cmd, "Missing --network none"
    assert "--read-only" in cmd, "Missing --read-only"
    assert any("tmpfs" in arg for arg in cmd), "Missing --tmpfs"
    assert "--memory" in cmd, "Missing --memory"
    assert "--cpus" in cmd, "Missing --cpus"
    assert "no-new-privileges:true" in cmd_str, "Missing --security-opt no-new-privileges"


def test_firmware_mounted_read_only(synthetic_firmware_file, tmp_path):
    """The firmware file volume mount must end with :ro."""
    out_dir = tmp_path / "out"
    captured: list[list[str]] = []

    def capture(cmd, **kwargs):
        captured.append(list(cmd))
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.json").write_text(json.dumps(_FAKE_REPORT))
        return MagicMock(returncode=0, stderr="")

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch.object(sandbox, "_image_exists", return_value=True):
            with patch("subprocess.run", side_effect=capture):
                sandbox.run_in_docker(synthetic_firmware_file, out_dir)

    cmd = captured[0]
    # Find the -v argument that refers to the firmware file
    v_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    firmware_mounts = [v for v in v_args if "input" in v or firmware_path_str(synthetic_firmware_file) in v]
    assert firmware_mounts, "No input volume mount found"
    assert all(v.endswith(":ro") for v in firmware_mounts), \
        f"Firmware mount not read-only: {firmware_mounts}"


def firmware_path_str(p: Path) -> str:
    return str(p.resolve()).replace("\\", "/")


# ── build_image ───────────────────────────────────────────────────────────────

def test_build_image_nonzero_raises():
    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", return_value=MagicMock(returncode=1)):
            with pytest.raises(sandbox.SandboxError, match="build failed"):
                sandbox.build_image()


def test_build_image_success():
    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            sandbox.build_image()  # should not raise
