"""Tests for ghidra_runner.py — Ghidra itself is never installed in CI/dev,
so all execution paths are exercised via mocking, mirroring test_sandbox.py."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from firmware_scanner import ghidra_runner


# ── is_available() ───────────────────────────────────────────────────────────

def test_is_available_false_without_env_var(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    assert not ghidra_runner.is_available()


def test_is_available_false_when_analyzer_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    assert not ghidra_runner.is_available()


def test_is_available_true_when_analyzer_present(monkeypatch, tmp_path):
    script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    support_dir = tmp_path / "support"
    support_dir.mkdir()
    (support_dir / script_name).write_text("#!/bin/sh\n")
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    assert ghidra_runner.is_available()


# ── decompile(): unavailable ──────────────────────────────────────────────────

def test_decompile_unavailable_returns_dict_not_raise(monkeypatch, tmp_path):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    result = ghidra_runner.decompile(tmp_path / "fw.bin", tmp_path / "out")
    assert result["available"] is False
    assert result["error"] is not None
    assert result["functions"] == []


# ── decompile(): mocked execution ────────────────────────────────────────────

@pytest.fixture
def fake_ghidra_home(monkeypatch, tmp_path):
    script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    support_dir = tmp_path / "support"
    support_dir.mkdir()
    (support_dir / script_name).write_text("#!/bin/sh\n")
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    return tmp_path


def test_decompile_timeout_returns_error(fake_ghidra_home, tmp_path):
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ghidra", timeout=1)):
        result = ghidra_runner.decompile(tmp_path / "fw.bin", tmp_path / "out", timeout=1)
    assert result["available"] is True
    assert "timed out" in result["error"]
    assert result["functions"] == []


def test_decompile_nonzero_exit_returns_error(fake_ghidra_home, tmp_path):
    with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="boom")):
        result = ghidra_runner.decompile(tmp_path / "fw.bin", tmp_path / "out")
    assert result["available"] is True
    assert "exited with code 1" in result["error"]


def test_decompile_missing_output_file_returns_error(fake_ghidra_home, tmp_path):
    with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="")):
        result = ghidra_runner.decompile(tmp_path / "fw.bin", tmp_path / "out")
    assert result["available"] is True
    assert "no output" in result["error"]


def test_decompile_success_parses_functions(fake_ghidra_home, tmp_path):
    out_dir = tmp_path / "out"
    fake_functions = [{"name": "main", "address": "0x1000", "code": "int main() { return 0; }"}]

    def fake_run(cmd, **kwargs):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "decompiled.json").write_text(json.dumps(fake_functions))
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        result = ghidra_runner.decompile(tmp_path / "fw.bin", out_dir)

    assert result["available"] is True
    assert result["error"] is None
    assert result["functions"] == fake_functions


def test_decompile_corrupt_output_returns_error(fake_ghidra_home, tmp_path):
    out_dir = tmp_path / "out"

    def fake_run(cmd, **kwargs):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "decompiled.json").write_text("not valid json {{{")
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        result = ghidra_runner.decompile(tmp_path / "fw.bin", out_dir)

    assert result["available"] is True
    assert "Failed to parse" in result["error"]
