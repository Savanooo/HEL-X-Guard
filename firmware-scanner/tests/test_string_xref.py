"""Tests for Feature 5: string/finding → code xref (Ghidra-dependent)."""
from __future__ import annotations

import pytest
from firmware_scanner import string_xref


# ── helpers ───────────────────────────────────────────────────────────────────

def _decompile(functions=(), *, available=True, error=None):
    return {"available": available, "error": error, "functions": list(functions)}


def _fn(name: str, address: str, code: str) -> dict:
    return {"name": name, "address": address, "code": code}


def _strings(suspicious=()):
    return {"suspicious": list(suspicious), "total": len(list(suspicious))}


def _str(value: str, category: str = "CREDENTIAL", offset: int = 0) -> dict:
    return {"value": value, "category": category, "offset": offset, "encoding": "ascii"}


# ── import ────────────────────────────────────────────────────────────────────

def test_string_xref_importable():
    from firmware_scanner import string_xref as sx  # noqa: F401
    assert hasattr(sx, "analyze")


# ── structure ─────────────────────────────────────────────────────────────────

def test_returns_correct_keys():
    result = string_xref.analyze(_decompile(), _strings())
    assert "available" in result
    assert "xrefs" in result
    assert "error" in result


def test_empty_decompile_returns_empty_xrefs():
    result = string_xref.analyze(_decompile(functions=[]), _strings())
    assert result["available"] is True
    assert result["xrefs"] == []
    assert result["error"] is None


def test_unavailable_decompile_returns_false():
    result = string_xref.analyze(_decompile(available=False), _strings())
    assert result["available"] is False
    assert result["xrefs"] == []


# ── basic matching ────────────────────────────────────────────────────────────

def test_string_found_in_function_code():
    """A suspicious string that appears in a function's pseudo-C is reported."""
    fns = [_fn("check_auth", "0x08001000", 'if (strcmp(password, "admin123") == 0) {')]
    strs = _strings([_str("admin123", "CREDENTIAL")])
    result = string_xref.analyze(_decompile(fns), strs)
    assert result["available"] is True
    assert len(result["xrefs"]) == 1
    xr = result["xrefs"][0]
    assert xr["value"] == "admin123"
    assert xr["category"] == "CREDENTIAL"
    assert len(xr["functions"]) == 1
    assert xr["functions"][0]["name"] == "check_auth"


def test_string_not_in_any_function_is_excluded():
    """A suspicious string not found in any function code produces no xref entry."""
    fns = [_fn("do_something", "0x08001000", "some unrelated code")]
    strs = _strings([_str("admin123", "CREDENTIAL")])
    result = string_xref.analyze(_decompile(fns), strs)
    assert result["xrefs"] == []


def test_string_found_in_multiple_functions():
    """A string that appears in multiple functions is listed under each."""
    fns = [
        _fn("fn_a", "0x08001000", 'char *pw = "secret_key_xyz";'),
        _fn("fn_b", "0x08002000", 'validate("secret_key_xyz");'),
        _fn("fn_c", "0x08003000", "unrelated code here"),
    ]
    strs = _strings([_str("secret_key_xyz", "API_KEY")])
    result = string_xref.analyze(_decompile(fns), strs)
    assert len(result["xrefs"]) == 1
    matched_names = {f["name"] for f in result["xrefs"][0]["functions"]}
    assert "fn_a" in matched_names
    assert "fn_b" in matched_names
    assert "fn_c" not in matched_names


def test_max_per_finding_limit():
    """The number of functions per xref entry is capped by max_per_finding."""
    fns = [_fn(f"fn_{i}", f"0x{0x8001000 + i*0x100:08x}", 'strcpy(buf, "hardcoded");') for i in range(10)]
    strs = _strings([_str("hardcoded", "DEBUG_KEYWORD")])
    result = string_xref.analyze(_decompile(fns), strs, max_per_finding=3)
    assert len(result["xrefs"][0]["functions"]) == 3


# ── deduplication ─────────────────────────────────────────────────────────────

def test_duplicate_string_values_deduplicated():
    """The same string value appearing twice in suspicious list is processed once."""
    fns = [_fn("fn_a", "0x08001000", 'use("duplicate_val");')]
    strs = _strings([
        _str("duplicate_val", "URL"),
        _str("duplicate_val", "DOMAIN"),  # same value, different category
    ])
    result = string_xref.analyze(_decompile(fns), strs)
    dup_entries = [x for x in result["xrefs"] if x["value"] == "duplicate_val"]
    assert len(dup_entries) == 1  # processed once


def test_very_short_strings_skipped():
    """Strings shorter than 4 characters are skipped to avoid false positives."""
    fns = [_fn("fn", "0x8000000", "int i = 0; if (x) {}")]
    strs = _strings([_str("if", "SHELL_COMMAND"), _str("int", "DEBUG_KEYWORD")])
    result = string_xref.analyze(_decompile(fns), strs)
    assert result["xrefs"] == []


# ── Thumb address handling ────────────────────────────────────────────────────

def test_thumb_bit_masked():
    """Addresses with Thumb LSB set are stored with bit masked out."""
    fns = [_fn("my_isr", "0x08001001", 'handle_fault();')]  # 0x...001 = Thumb
    strs = _strings([_str("handle_fault", "DEBUG_KEYWORD")])
    result = string_xref.analyze(_decompile(fns), strs)
    assert len(result["xrefs"]) == 1
    addr = result["xrefs"][0]["functions"][0]["address"]
    assert addr == "0x08001000"  # Thumb bit cleared


def test_clean_addr_plain():
    assert string_xref._clean_addr("0x08001234") == "0x08001234"


def test_clean_addr_thumb():
    assert string_xref._clean_addr("0x08001235") == "0x08001234"


def test_clean_addr_bad_input():
    addr = string_xref._clean_addr("not_hex")
    assert isinstance(addr, str)  # returns something, doesn't raise


# ── error resilience ──────────────────────────────────────────────────────────

def test_analyze_never_raises_on_bad_input():
    result = string_xref.analyze(None, None)  # type: ignore[arg-type]
    assert "error" in result
    assert isinstance(result["xrefs"], list)


def test_multiple_strings_multiple_functions():
    """Full integration scenario: multiple strings, multiple functions."""
    fns = [
        _fn("auth_check", "0x08001000", 'if (strcmp(user, "admin") == 0) {}'),
        _fn("network_init", "0x08002000", 'connect("192.168.1.100", 8080);'),
        _fn("crypto_algo", "0x08003000", 'rc4_encrypt(key, data);'),
    ]
    strs = _strings([
        _str("admin",       "CREDENTIAL"),
        _str("192.168.1.100", "IP"),
        _str("rc4_encrypt", "CRYPTO"),
        _str("not_present", "URL"),
    ])
    result = string_xref.analyze(_decompile(fns), strs)
    assert result["available"] is True
    values_with_xref = {x["value"] for x in result["xrefs"]}
    assert "admin" in values_with_xref
    assert "192.168.1.100" in values_with_xref
    assert "rc4_encrypt" in values_with_xref
    assert "not_present" not in values_with_xref
