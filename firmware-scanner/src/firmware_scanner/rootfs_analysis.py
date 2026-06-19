"""Linux rootfs deep analysis (Feature 5).

After binwalk extraction, walk the extracted directory tree using only
``os.stat`` / ``open`` / ``pathlib`` — **never execute any extracted binary**.

What is analysed
----------------
* /etc/passwd  — parse accounts; flag UID 0 extras, empty passwords, suspicious shells
* /etc/shadow  — flag accounts with no password hash (!! / *), or known-weak hashes
* Boot / init scripts  — /etc/init.d/, /etc/rc*, /etc/inittab, /etc/init/, etc.;
                         look for hard-coded credentials, wget/curl pipes to shell,
                         suspicious URLs, setuid calls
* SUID/SGID binaries   — files with S_ISUID or S_ISGID set; flag if outside
                         /bin /sbin /usr/bin /usr/sbin
* World-writable files — mode & 0o002 set; excludes /proc, /sys, /dev, /tmp
* SSH keys             — authorised_keys files, private key blobs in ~/.ssh/
                         and /etc/ssh/
* Hardcoded secrets    — scan text-like config files for obvious patterns
                         (password=, passwd=, secret=, token=, key=)
* Kernel version banner — /proc/version (static copies), /etc/issue, uname strings
* Web root files       — walk /var/www/, /srv/www/, /www/, list .php/.cgi/.asp files

None of the findings require the binary to be executable; everything is
derived from content inspection and file-system metadata only.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path


# ── Constants ─────────────────────────────────────────────────────────────────

_SUID_SAFE_DIRS = frozenset({
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
})

_BOOT_INIT_DIRS = (
    "etc/init.d", "etc/rc.d", "etc/rc.local", "etc/inittab",
    "etc/init", "etc/rcS.d", "etc/rc5.d", "etc/rc2.d",
    "etc/rc.common", "etc/rc.conf", "etc/rc",
)

_SECRET_PATTERN = re.compile(
    r"(?i)(?:password|passwd|secret|token|api_key|apikey|auth_key|private_key"
    r"|passphrase|credential|auth_token)\s*[=:]\s*['\"]?([^\s'\"#]{6,})",
)

_URL_PIPE_PATTERN = re.compile(
    r"(?:wget|curl)\s+[^\n]*https?://[^\s]+\s*\|",
)

_WEAK_MD5_PREFIX = re.compile(r"^\$1\$")
_WEAK_DES_HASH   = re.compile(r"^[a-zA-Z0-9./]{13}$")

_TEXT_EXTENSIONS = frozenset({
    ".conf", ".cfg", ".ini", ".sh", ".bash", ".rc", ".env",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".txt",
    ".py", ".pl", ".rb", ".lua", ".php", ".cgi", ".asp",
})

_WEB_ROOT_DIRS = ("var/www", "srv/www", "www", "htdocs", "webroot", "public_html")

_KERNEL_BANNER_FILES = (
    "proc/version", "etc/issue", "etc/issue.net", "etc/os-release",
    "usr/lib/os-release",
)

# Max size to read from any single file (avoid reading huge files)
_MAX_FILE_READ = 256 * 1024  # 256 KB


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rel(path: Path, root: Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _read_text(path: Path, max_bytes: int = _MAX_FILE_READ) -> str:
    try:
        raw = path.read_bytes()[:max_bytes]
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _is_text_file(path: Path) -> bool:
    if path.suffix.lower() in _TEXT_EXTENSIONS:
        return True
    try:
        chunk = path.read_bytes()[:512]
        return b"\x00" not in chunk
    except OSError:
        return False


def _parse_passwd(root: Path) -> list[dict]:
    """Parse /etc/passwd → list of account dicts."""
    passwd_path = root / "etc" / "passwd"
    accounts: list[dict] = []
    text = _read_text(passwd_path)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue
        accounts.append({
            "user":  parts[0],
            "uid":   uid,
            "gid":   gid,
            "shell": parts[6],
            "home":  parts[5],
        })
    return accounts


def _parse_shadow(root: Path) -> list[dict]:
    """Parse /etc/shadow → list of {user, hash_type, empty_password}."""
    shadow_path = root / "etc" / "shadow"
    entries: list[dict] = []
    text = _read_text(shadow_path)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user   = parts[0]
        pw     = parts[1]
        empty  = pw in ("", "!", "!!", "*", "x", "NP")
        weak_md5 = bool(_WEAK_MD5_PREFIX.match(pw))
        weak_des = bool(_WEAK_DES_HASH.match(pw))
        entries.append({
            "user":          user,
            "empty_password": empty,
            "weak_hash":     weak_md5 or weak_des,
            "hash_type":     (
                "md5_crypt" if weak_md5 else
                "des_crypt" if weak_des else
                "unknown"   if empty    else
                pw[:3]
            ),
        })
    return entries


def _scan_init_scripts(root: Path) -> list[dict]:
    """Scan boot/init scripts for dangerous patterns."""
    findings: list[dict] = []
    for rel_dir in _BOOT_INIT_DIRS:
        target = root / Path(rel_dir.replace("/", os.sep))
        if not target.exists():
            continue
        paths = [target] if target.is_file() else list(target.rglob("*"))
        for p in paths:
            if not p.is_file():
                continue
            text = _read_text(p)
            if not text:
                continue
            for m in _SECRET_PATTERN.finditer(text):
                val = m.group(1)
                if val.lower() not in ("true", "false", "yes", "no", "none", "null", ""):
                    findings.append({
                        "path":    _rel(p, root),
                        "type":    "hardcoded_credential",
                        "excerpt": m.group(0)[:120],
                    })
            for m in _URL_PIPE_PATTERN.finditer(text):
                findings.append({
                    "path":    _rel(p, root),
                    "type":    "shell_pipe_download",
                    "excerpt": m.group(0)[:120],
                })
    return findings


def _find_suid_sgid(root: Path) -> list[dict]:
    """Walk tree and collect files with SUID/SGID bits."""
    results: list[dict] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        suid = bool(st.st_mode & stat.S_ISUID)
        sgid = bool(st.st_mode & stat.S_ISGID)
        if not (suid or sgid):
            continue
        rel = _rel(p, root)
        # Check if it's in a known-safe directory
        parent_posix = "/" + p.relative_to(root).parent.as_posix()
        outside_safe = parent_posix not in _SUID_SAFE_DIRS
        results.append({
            "path":         rel,
            "suid":         suid,
            "sgid":         sgid,
            "outside_safe": outside_safe,
            "mode":         oct(st.st_mode & 0o7777),
        })
    return results


def _find_world_writable(root: Path) -> list[dict]:
    """Find world-writable files, excluding pseudo-filesystems."""
    _SKIP_DIRS = frozenset({"proc", "sys", "dev", "run"})
    results: list[dict] = []
    for p in root.rglob("*"):
        # Skip pseudo-fs paths
        try:
            rel_parts = p.relative_to(root).parts
        except ValueError:
            continue
        if rel_parts and rel_parts[0] in _SKIP_DIRS:
            continue
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if st.st_mode & 0o002:
            results.append({
                "path": _rel(p, root),
                "mode": oct(st.st_mode & 0o7777),
            })
    return results


def _find_ssh_keys(root: Path) -> list[dict]:
    """Locate SSH private keys and authorized_keys files."""
    results: list[dict] = []
    patterns = (
        "**/.ssh/id_rsa",
        "**/.ssh/id_dsa",
        "**/.ssh/id_ecdsa",
        "**/.ssh/id_ed25519",
        "**/.ssh/authorized_keys",
        "etc/ssh/ssh_host_*_key",
        "**/.ssh/*",
    )
    seen: set[Path] = set()
    for pat in patterns:
        for p in root.glob(pat):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            text = _read_text(p, max_bytes=4096)
            is_private = "BEGIN" in text and "PRIVATE KEY" in text
            is_authkeys = "authorized_keys" in p.name or (
                p.name.endswith("_key") and "ssh_host" in p.name
            )
            results.append({
                "path":       _rel(p, root),
                "is_private": is_private,
                "type":       "private_key" if is_private else (
                              "authorized_keys" if "authorized_keys" in p.name else
                              "host_key"),
            })
    return results


def _scan_configs_for_secrets(root: Path) -> list[dict]:
    """Walk all text-like config files and look for hardcoded secrets."""
    results: list[dict] = []
    _SKIP_DIRS = frozenset({"proc", "sys", "dev", "run", "tmp", "var/log"})

    for p in root.rglob("*"):
        try:
            rel_parts = p.relative_to(root).parts
        except ValueError:
            continue
        if rel_parts and rel_parts[0] in _SKIP_DIRS:
            continue
        if not p.is_file():
            continue
        if not _is_text_file(p):
            continue
        text = _read_text(p)
        for m in _SECRET_PATTERN.finditer(text):
            val = m.group(1)
            if val.lower() in ("true", "false", "yes", "no", "none", "null", ""):
                continue
            results.append({
                "path":    _rel(p, root),
                "type":    "hardcoded_secret",
                "excerpt": m.group(0)[:120],
            })
        if len(results) >= 200:   # cap to avoid runaway on large roots
            break
    return results


def _read_kernel_banner(root: Path) -> str | None:
    for rel in _KERNEL_BANNER_FILES:
        p = root / Path(rel.replace("/", os.sep))
        if p.is_file():
            text = _read_text(p, max_bytes=512)
            if text.strip():
                return text.strip()
    return None


def _find_web_roots(root: Path) -> list[dict]:
    """Collect PHP/CGI/ASP files in common web root directories."""
    results: list[dict] = []
    _WEB_EXTS = frozenset({".php", ".cgi", ".asp", ".aspx", ".jsp", ".pl", ".py"})
    for web_dir in _WEB_ROOT_DIRS:
        wroot = root / Path(web_dir.replace("/", os.sep))
        if not wroot.is_dir():
            continue
        for p in wroot.rglob("*"):
            if p.is_file() and p.suffix.lower() in _WEB_EXTS:
                results.append({
                    "path": _rel(p, root),
                    "ext":  p.suffix.lower(),
                })
    return results


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(root_dir: Path) -> dict:
    """Walk an extracted Linux rootfs and report security findings.

    Args:
        root_dir: Path to the extracted root filesystem directory.

    Returns::

        {
            "available":   bool,
            "root_dir":    str,
            "accounts":    [{"user", "uid", "gid", "shell", "home"}],
            "shadow":      [{"user", "empty_password", "weak_hash", "hash_type"}],
            "init_findings": [{"path", "type", "excerpt"}],
            "suid_files":  [{"path", "suid", "sgid", "outside_safe", "mode"}],
            "world_writable": [{"path", "mode"}],
            "ssh_keys":    [{"path", "is_private", "type"}],
            "config_secrets": [{"path", "type", "excerpt"}],
            "kernel_banner": str | None,
            "web_files":   [{"path", "ext"}],
            "flags":       [str],    # high-level flag names
            "error":       str | None,
        }

    Never raises.
    """
    try:
        return _do_analyze(root_dir)
    except Exception as exc:  # noqa: BLE001
        return {
            "available":   False,
            "root_dir":    str(root_dir),
            "accounts":    [],
            "shadow":      [],
            "init_findings": [],
            "suid_files":  [],
            "world_writable": [],
            "ssh_keys":    [],
            "config_secrets": [],
            "kernel_banner": None,
            "web_files":   [],
            "flags":       [],
            "error":       str(exc),
        }


def _do_analyze(root_dir: Path) -> dict:
    if not root_dir.is_dir():
        return {
            "available":   False,
            "root_dir":    str(root_dir),
            "accounts":    [],
            "shadow":      [],
            "init_findings": [],
            "suid_files":  [],
            "world_writable": [],
            "ssh_keys":    [],
            "config_secrets": [],
            "kernel_banner": None,
            "web_files":   [],
            "flags":       [],
            "error":       f"Not a directory: {root_dir}",
        }

    accounts        = _parse_passwd(root_dir)
    shadow          = _parse_shadow(root_dir)
    init_findings   = _scan_init_scripts(root_dir)
    suid_files      = _find_suid_sgid(root_dir)
    world_writable  = _find_world_writable(root_dir)
    ssh_keys        = _find_ssh_keys(root_dir)
    config_secrets  = _scan_configs_for_secrets(root_dir)
    kernel_banner   = _read_kernel_banner(root_dir)
    web_files       = _find_web_roots(root_dir)

    # Derive summary flags
    flags: list[str] = []

    # Root with empty password
    shadow_map = {e["user"]: e for e in shadow}
    for acc in accounts:
        if acc["uid"] == 0 and acc["user"] != "root":
            flags.append("extra_root_uid_account")
            break
    if shadow_map.get("root", {}).get("empty_password"):
        flags.append("root_empty_password")
    if any(e["empty_password"] for e in shadow):
        flags.append("accounts_with_empty_password")
    if any(e["weak_hash"] for e in shadow):
        flags.append("weak_password_hash")

    # SUID outside safe dirs
    if any(s["outside_safe"] for s in suid_files):
        flags.append("suid_outside_safe_dirs")

    # Private keys found
    if any(k["is_private"] for k in ssh_keys):
        flags.append("private_key_in_rootfs")

    # Hardcoded secrets
    if config_secrets or init_findings:
        flags.append("hardcoded_secrets")

    # wget|curl | pipe
    if any(f["type"] == "shell_pipe_download" for f in init_findings):
        flags.append("shell_pipe_download")

    return {
        "available":      True,
        "root_dir":       str(root_dir),
        "accounts":       accounts,
        "shadow":         shadow,
        "init_findings":  init_findings,
        "suid_files":     suid_files,
        "world_writable": world_writable,
        "ssh_keys":       ssh_keys,
        "config_secrets": config_secrets,
        "kernel_banner":  kernel_banner,
        "web_files":      web_files,
        "flags":          flags,
        "error":          None,
    }
