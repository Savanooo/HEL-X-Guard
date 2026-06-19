"""Tests for the YARA rule management API (Feature 2).

These tests exercise the validate endpoint and the CRUD schema objects in
isolation, without requiring a running server or database.
"""
from __future__ import annotations

import pytest

# ── yara availability ─────────────────────────────────────────────────────────

def _yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


requires_yara = pytest.mark.skipif(
    not _yara_available(), reason="yara-python not installed"
)


# ── validate logic (isolated, no FastAPI test client needed) ──────────────────

@requires_yara
def test_valid_yara_compiles():
    """A syntactically correct YARA rule compiles without error."""
    import yara

    good = """
rule GoodRule
{
    meta:
        severity = "low"
    strings:
        $s = "hello world"
    condition:
        $s
}
"""
    yara.compile(source=good)  # must not raise


@requires_yara
def test_invalid_yara_raises():
    """A malformed YARA rule fails to compile."""
    import yara

    bad = "rule Bad { this is not valid yara syntax !!!}"
    with pytest.raises(Exception):
        yara.compile(source=bad)


@requires_yara
def test_severity_metadata_field():
    """Rules can carry a severity metadata field without compile errors."""
    import yara

    for sev in ("low", "medium", "high", "critical"):
        src = f"""
rule SeverityTest_{sev}
{{
    meta:
        severity = "{sev}"
    strings:
        $s = "{sev}"
    condition:
        $s
}}
"""
        yara.compile(source=src)


# ── schema validation (Pydantic, no DB) ──────────────────────────────────────

def test_yara_rule_create_schema_defaults():
    """YaraRuleCreate sets sensible defaults."""
    from firmware_scanner import firmware_loader  # noqa (import check)
    from api.schemas import YaraRuleCreate

    rule = YaraRuleCreate(name="TestRule", content="rule T { condition: false }")
    assert rule.severity == "medium"
    assert rule.enabled is True
    assert rule.description == ""


def test_yara_rule_update_all_optional():
    """YaraRuleUpdate allows partial updates (all fields optional)."""
    from api.schemas import YaraRuleUpdate

    update = YaraRuleUpdate()
    assert update.name is None
    assert update.content is None
    assert update.enabled is None


def test_yara_validate_request_schema():
    """YaraValidateRequest wraps the content field."""
    from api.schemas import YaraValidateRequest

    req = YaraValidateRequest(content="rule X { condition: false }")
    assert req.content.startswith("rule")


def test_yara_validate_response_schema():
    """YaraValidateResponse has ok and error fields."""
    from api.schemas import YaraValidateResponse

    ok_resp = YaraValidateResponse(ok=True)
    assert ok_resp.ok is True
    assert ok_resp.error is None

    fail_resp = YaraValidateResponse(ok=False, error="syntax error at line 1")
    assert fail_resp.ok is False
    assert "syntax" in fail_resp.error


# ── router import sanity ──────────────────────────────────────────────────────

def test_rules_router_importable():
    """The rules router module can be imported without error."""
    from api.routers import rules  # noqa: F401
    assert hasattr(rules, "router")


def test_rules_router_has_expected_routes():
    """The rules router exposes the expected path prefixes."""
    from api.routers.rules import router

    paths = {r.path for r in router.routes}
    assert "/api/v1/rules" in paths
    assert "/api/v1/rules/validate" in paths
    assert "/api/v1/rules/{rule_id}" in paths
