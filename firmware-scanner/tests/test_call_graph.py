"""Tests for Feature 6: library-function naming + call graph."""
from __future__ import annotations

import pytest

from firmware_scanner import call_graph
from firmware_scanner.call_graph import (
    _infer_name,
    _clean_addr,
    _build_call_graph,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_decompile(functions: list[dict]) -> dict:
    """Create a minimal decompile_result dict from a function list."""
    return {"available": True, "functions": functions}


FREERTOS_TASK = {
    "name": "FUN_08001000",
    "address": "0x08001000",
    "code": (
        "void FUN_08001000(void) {\n"
        "  xTaskCreate(sensor_task, 'Sensor', 256, NULL, 1, &sensor_handle);\n"
        "  vTaskStartScheduler();\n"
        "}"
    ),
}

MALLOC_FN = {
    "name": "FUN_08002000",
    "address": "0x08002000",
    "code": (
        "void* FUN_08002000(int size) {\n"
        "  void* p = malloc(size);\n"
        "  return p;\n"
        "}"
    ),
}

CALLER_FN = {
    "name": "FUN_08003000",
    "address": "0x08003000",
    "code": (
        "void FUN_08003000(void) {\n"
        "  FUN_08001000();\n"
        "  FUN_08002000(64);\n"
        "}"
    ),
}

UART_FN = {
    "name": "FUN_08004000",
    "address": "0x08004000",
    "code": (
        "void FUN_08004000(void) {\n"
        "  HAL_UART_Transmit(&huart1, buf, 10, 100);\n"
        "}"
    ),
}

SIMPLE_FN = {
    "name": "main",
    "address": "0x08000000",
    "code": "int main(void) { return 0; }",
}


# ── Structure ─────────────────────────────────────────────────────────────────

def test_analyze_returns_dict():
    r = call_graph.analyze(_make_decompile([SIMPLE_FN]))
    assert isinstance(r, dict)


def test_analyze_required_keys():
    r = call_graph.analyze(_make_decompile([SIMPLE_FN]))
    for k in ("available", "named_functions", "call_graph",
              "callers_by_address", "callees_by_address", "error"):
        assert k in r


def test_analyze_call_graph_required_keys():
    r = call_graph.analyze(_make_decompile([SIMPLE_FN]))
    assert "nodes" in r["call_graph"]
    assert "edges" in r["call_graph"]


def test_analyze_empty_functions():
    r = call_graph.analyze(_make_decompile([]))
    assert r["available"] is True
    assert r["named_functions"] == []
    assert r["call_graph"] == {"nodes": [], "edges": []}


def test_analyze_unavailable_decompile():
    r = call_graph.analyze({"available": False, "functions": []})
    assert r["available"] is False


def test_analyze_never_raises():
    r = call_graph.analyze({"available": True, "functions": None})
    assert isinstance(r, dict)


# ── Function naming ───────────────────────────────────────────────────────────

def test_freertos_task_inferred():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK]))
    named = r["named_functions"]
    assert len(named) >= 1
    names = [n["inferred_name"] for n in named]
    assert any("FreeRTOS" in n for n in names)


def test_malloc_wrapper_inferred():
    r = call_graph.analyze(_make_decompile([MALLOC_FN]))
    named = r["named_functions"]
    assert any("heap" in n["inferred_name"] or "alloc" in n["inferred_name"]
               for n in named)


def test_uart_hal_inferred():
    r = call_graph.analyze(_make_decompile([UART_FN]))
    named = r["named_functions"]
    assert any("uart" in n["inferred_name"].lower() for n in named)


def test_no_match_no_naming():
    r = call_graph.analyze(_make_decompile([SIMPLE_FN]))
    assert r["named_functions"] == []


def test_named_function_has_required_fields():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK]))
    for n in r["named_functions"]:
        assert "address" in n
        assert "original_name" in n
        assert "inferred_name" in n
        assert "confidence" in n
        assert "basis" in n


def test_infer_name_freertos():
    code = "xTaskCreate(my_task, 'T', 128, NULL, 1, NULL);"
    name, conf, basis = _infer_name(code)
    assert name is not None
    assert "FreeRTOS" in name
    assert conf in ("high", "medium")


def test_infer_name_no_match():
    name, conf, basis = _infer_name("return 42;")
    assert name is None
    assert conf == ""


def test_infer_name_hal_uart():
    code = "HAL_UART_Transmit(&h, buf, 8, 100);"
    name, conf, _ = _infer_name(code)
    assert name is not None
    assert "uart" in name.lower()
    assert conf == "high"


# ── Call graph ────────────────────────────────────────────────────────────────

def test_call_graph_nodes_count():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK, MALLOC_FN, CALLER_FN]))
    assert len(r["call_graph"]["nodes"]) == 3


def test_call_graph_edges_caller_to_callee():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK, MALLOC_FN, CALLER_FN]))
    edges = r["call_graph"]["edges"]
    caller_addr = _clean_addr("0x08003000")
    callee1     = _clean_addr("0x08001000")
    callee2     = _clean_addr("0x08002000")
    assert any(e["caller"] == caller_addr and e["callee"] == callee1 for e in edges)
    assert any(e["caller"] == caller_addr and e["callee"] == callee2 for e in edges)


def test_call_graph_no_self_loops():
    fn = {
        "name": "FUN_08000100",
        "address": "0x08000100",
        "code": "void FUN_08000100(void) { FUN_08000100(); }",
    }
    r = call_graph.analyze(_make_decompile([fn]))
    for e in r["call_graph"]["edges"]:
        assert e["caller"] != e["callee"]


def test_call_graph_no_duplicate_edges():
    fn = {
        "name": "FUN_08000200",
        "address": "0x08000200",
        "code": "void FUN_08000200(void) {}",
    }
    caller = {
        "name": "FUN_08000300",
        "address": "0x08000300",
        "code": "void FUN_08000300(void) { FUN_08000200(); FUN_08000200(); }",
    }
    r = call_graph.analyze(_make_decompile([fn, caller]))
    edges = [(e["caller"], e["callee"]) for e in r["call_graph"]["edges"]]
    assert len(edges) == len(set(edges))


def test_callees_by_address_populated():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK, MALLOC_FN, CALLER_FN]))
    caller_addr = _clean_addr("0x08003000")
    callees = r["callees_by_address"].get(caller_addr, [])
    assert _clean_addr("0x08001000") in callees
    assert _clean_addr("0x08002000") in callees


def test_callers_by_address_populated():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK, MALLOC_FN, CALLER_FN]))
    callee_addr = _clean_addr("0x08001000")
    callers = r["callers_by_address"].get(callee_addr, [])
    assert _clean_addr("0x08003000") in callers


def test_function_with_no_calls_has_empty_callees():
    r = call_graph.analyze(_make_decompile([FREERTOS_TASK, CALLER_FN]))
    ft_addr = _clean_addr("0x08001000")
    assert r["callees_by_address"].get(ft_addr, []) == []


# ── _clean_addr ───────────────────────────────────────────────────────────────

def test_clean_addr_thumb_bit_masked():
    assert _clean_addr("0x08001001") == "0x08001000"


def test_clean_addr_normal():
    assert _clean_addr("0x08001000") == "0x08001000"


def test_clean_addr_invalid():
    result = _clean_addr("not_an_addr")
    assert isinstance(result, str)


# ── Build call graph helper ───────────────────────────────────────────────────

def test_build_call_graph_returns_lists():
    functions = [
        {"name": "a", "_addr": "0x100", "code": "b();"},
        {"name": "b", "_addr": "0x200", "code": ""},
    ]
    addr_by_name = {"a": "0x100", "b": "0x200"}
    name_by_addr = {"0x100": "a", "0x200": "b"}
    nodes, edges = _build_call_graph(functions, addr_by_name, name_by_addr)
    assert isinstance(nodes, list)
    assert isinstance(edges, list)
