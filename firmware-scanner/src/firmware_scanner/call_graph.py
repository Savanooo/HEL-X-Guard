"""Library-function naming and call-graph construction (Feature 6).

Operates purely on the decompile JSON produced by ghidra_runner — no
additional Ghidra invocations, no subprocess calls.

What this module does
---------------------
1. **Function naming** — scan each function's decompiled C code for:
   - Well-known libc / POSIX symbols (malloc, free, memcpy, printf, …)
   - FreeRTOS API calls (xTaskCreate, vTaskDelay, xQueueSend, …)
   - LWIP / networking symbols (pbuf_alloc, netif_add, …)
   - Known format-string patterns that uniquely identify a function

   When a match is found the function is labelled with an ``inferred_name``
   and a ``confidence`` ("high" / "medium").  The label does not replace the
   Ghidra name — it supplements it.

2. **Call graph** — extract caller → callee edges:
   - Ghidra-named calls: ``FUN_XXXXXXXX(`` pattern
   - Named calls: any token of the form ``[a-zA-Z_][a-zA-Z0-9_]+(`` that
     matches another known function name in the decompile output
   - Returns a deduplicated edge list and per-function caller / callee maps

Output schema::

    {
        "available":        bool,
        "named_functions":  [
            {
                "address":       str,
                "original_name": str,
                "inferred_name": str,
                "confidence":    str,   # "high" | "medium"
                "basis":         str,   # e.g. "calls xTaskCreate"
            }
        ],
        "call_graph": {
            "nodes": [{"address": str, "name": str}],
            "edges": [{"caller": str, "callee": str}],  # address → address
        },
        "callers_by_address": {addr: [caller_addr, ...]},
        "callees_by_address": {addr: [callee_addr, ...]},
        "error": str | None,
    }
"""
from __future__ import annotations

import re


# ── Known API symbol → inferred name mapping ─────────────────────────────────
# Format: (regex_pattern, inferred_name, confidence)
# Matched against the full decompiled code of a function.

_NAMING_RULES: list[tuple[str, str, str]] = [
    # FreeRTOS
    (r"\bxTaskCreate\b",         "FreeRTOS_TaskEntry",      "high"),
    (r"\bvTaskDelay\b",          "FreeRTOS_DelayTask",      "medium"),
    (r"\bxQueueCreate\b",        "FreeRTOS_QueueInit",      "medium"),
    (r"\bxQueueSend\b",          "FreeRTOS_QueueSender",    "medium"),
    (r"\bxQueueReceive\b",       "FreeRTOS_QueueReceiver",  "medium"),
    (r"\bvSemaphoreCreateBinary\b", "FreeRTOS_SemaphoreInit", "medium"),
    (r"\bxSemaphoreGive\b",      "FreeRTOS_SemaphoreGive",  "medium"),
    (r"\bxSemaphoreTake\b",      "FreeRTOS_SemaphoreTake",  "medium"),
    (r"\bvPortEnterCritical\b",  "FreeRTOS_CriticalSection","medium"),
    (r"\bvTaskStartScheduler\b", "FreeRTOS_StartScheduler", "high"),
    (r"\bvTaskDelete\b",         "FreeRTOS_TaskCleanup",    "medium"),
    # libc / newlib
    (r"\bmalloc\s*\(",           "heap_allocator",          "medium"),
    (r"\bcalloc\s*\(",           "heap_allocator",          "medium"),
    (r"\bfree\s*\(",             "heap_free",               "medium"),
    (r"\bmemcpy\s*\(",           "memcpy_wrapper",          "medium"),
    (r"\bmemset\s*\(",           "memset_wrapper",          "medium"),
    (r"\bstrlen\s*\(",           "string_util",             "medium"),
    (r"\bstrcpy\s*\(",           "string_copy",             "medium"),
    (r"\bprintf\s*\(",           "print_handler",           "medium"),
    (r"\bsprintf\s*\(",          "format_string_handler",   "medium"),
    (r"\bsnprintf\s*\(",         "format_string_handler",   "medium"),
    (r"\bputs\s*\(",             "print_handler",           "medium"),
    (r"\bsscanf\s*\(",           "input_parser",            "medium"),
    (r"\bfopen\s*\(",            "file_open",               "medium"),
    (r"\bfread\s*\(",            "file_read",               "medium"),
    (r"\bfwrite\s*\(",           "file_write",              "medium"),
    # LWIP networking
    (r"\bpbuf_alloc\b",          "lwip_packet_alloc",       "high"),
    (r"\bnetif_add\b",           "lwip_netif_setup",        "high"),
    (r"\btcp_connect\b",         "lwip_tcp_client",         "high"),
    (r"\budp_sendto\b",          "lwip_udp_sender",         "high"),
    (r"\bdhcp_start\b",          "lwip_dhcp_init",          "high"),
    # HAL (STM32 HAL)
    (r"\bHAL_UART_Transmit\b",   "hal_uart_tx",             "high"),
    (r"\bHAL_UART_Receive\b",    "hal_uart_rx",             "high"),
    (r"\bHAL_SPI_Transmit\b",    "hal_spi_tx",              "high"),
    (r"\bHAL_I2C_Master_Transmit\b", "hal_i2c_tx",          "high"),
    (r"\bHAL_GPIO_WritePin\b",   "hal_gpio_write",          "high"),
    (r"\bHAL_GPIO_ReadPin\b",    "hal_gpio_read",           "high"),
    (r"\bHAL_Delay\b",           "hal_delay",               "medium"),
    # Crypto
    (r"\bmbedtls_aes_crypt\b",   "mbedtls_aes",             "high"),
    (r"\bmbedtls_sha256\b",      "mbedtls_sha256",          "high"),
    (r"\bmbedtls_ssl_handshake\b", "mbedtls_tls_handshake", "high"),
    # Format-string heuristics
    (r'"FreeRTOS"',              "FreeRTOS_VersionCheck",   "high"),
    (r'"Task\s*\w+\s*created"',  "FreeRTOS_TaskEntry",      "medium"),
]

_NAMING_COMPILED = [(re.compile(pat), name, conf) for pat, name, conf in _NAMING_RULES]

# Regex: Ghidra auto-named functions  FUN_XXXXXXXX(
_GHIDRA_CALL = re.compile(r"\b(FUN_[0-9a-fA-F]{8})\s*\(")

# Regex: any C function call token (to match known-named functions)
_GENERIC_CALL = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_addr(addr: str) -> str:
    try:
        n = int(addr, 16) & ~1  # mask Thumb bit
        return f"0x{n:08x}"
    except (ValueError, TypeError):
        return addr or "0x00000000"


def _infer_name(code: str) -> tuple[str | None, str, str]:
    """Return (inferred_name, confidence, basis) or (None, '', '')."""
    for pattern, name, conf in _NAMING_COMPILED:
        m = pattern.search(code)
        if m:
            return name, conf, f"calls {m.group(0).strip()}"
    return None, "", ""


# ── Call graph builder ────────────────────────────────────────────────────────

def _build_call_graph(
    functions: list[dict],
    addr_by_name: dict[str, str],
    name_by_addr: dict[str, str],
) -> tuple[list[dict], list[dict]]:
    """Build nodes and edges for the call graph.

    Returns (nodes, edges) where:
      nodes: [{address, name}]
      edges: [{caller (addr), callee (addr)}]
    """
    nodes = [{"address": fn["_addr"], "name": fn["name"]} for fn in functions]
    edges: list[dict] = []
    seen_edges: set[tuple[str, str]] = set()

    for fn in functions:
        caller_addr = fn["_addr"]
        code        = fn.get("code") or ""

        # Collect all called identifiers from code
        candidates: set[str] = set()
        for m in _GHIDRA_CALL.finditer(code):
            candidates.add(m.group(1))
        for m in _GENERIC_CALL.finditer(code):
            tok = m.group(1)
            if tok in addr_by_name:
                candidates.add(tok)

        for tok in candidates:
            # Resolve to address
            callee_addr: str | None = None
            if tok.startswith("FUN_"):
                callee_addr = _clean_addr("0x" + tok[4:])
            elif tok in addr_by_name:
                callee_addr = addr_by_name[tok]

            if callee_addr is None:
                continue
            if callee_addr == caller_addr:
                continue   # skip self-loops
            if callee_addr not in name_by_addr:
                continue   # callee not in our function list

            edge_key = (caller_addr, callee_addr)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                edges.append({"caller": caller_addr, "callee": callee_addr})

    return nodes, edges


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(decompile_result: dict) -> dict:
    """Build function naming labels and caller/callee graph from Ghidra output.

    Args:
        decompile_result: Dict produced by ``ghidra_runner.decompile()``.

    Returns the call-graph schema (see module docstring). Never raises.
    """
    try:
        return _do_analyze(decompile_result)
    except Exception as exc:  # noqa: BLE001
        return {
            "available":          False,
            "named_functions":    [],
            "call_graph":         {"nodes": [], "edges": []},
            "callers_by_address": {},
            "callees_by_address": {},
            "error":              str(exc),
        }


def _do_analyze(decompile_result: dict) -> dict:
    if not decompile_result.get("available", True):
        return {
            "available":          False,
            "named_functions":    [],
            "call_graph":         {"nodes": [], "edges": []},
            "callers_by_address": {},
            "callees_by_address": {},
            "error":              "Ghidra decompilation not available",
        }

    raw_functions: list[dict] = decompile_result.get("functions", [])
    if not raw_functions:
        return {
            "available":          True,
            "named_functions":    [],
            "call_graph":         {"nodes": [], "edges": []},
            "callers_by_address": {},
            "callees_by_address": {},
            "error":              None,
        }

    # Normalise functions and index them
    functions: list[dict] = []
    addr_by_name: dict[str, str] = {}
    name_by_addr: dict[str, str] = {}

    for fn in raw_functions:
        name = fn.get("name") or "unknown"
        addr = _clean_addr(fn.get("address", ""))
        code = fn.get("code") or ""
        functions.append({"name": name, "_addr": addr, "code": code})
        addr_by_name[name] = addr
        name_by_addr[addr] = name

    # Function naming inference
    named_functions: list[dict] = []
    for fn in functions:
        inferred, conf, basis = _infer_name(fn["code"])
        if inferred:
            named_functions.append({
                "address":       fn["_addr"],
                "original_name": fn["name"],
                "inferred_name": inferred,
                "confidence":    conf,
                "basis":         basis,
            })

    # Call graph
    nodes, edges = _build_call_graph(functions, addr_by_name, name_by_addr)

    # Build per-function maps
    callees_by_address: dict[str, list[str]] = {fn["_addr"]: [] for fn in functions}
    callers_by_address: dict[str, list[str]] = {fn["_addr"]: [] for fn in functions}

    for edge in edges:
        callees_by_address[edge["caller"]].append(edge["callee"])
        callers_by_address[edge["callee"]].append(edge["caller"])

    return {
        "available":          True,
        "named_functions":    named_functions,
        "call_graph":         {"nodes": nodes, "edges": edges},
        "callers_by_address": callers_by_address,
        "callees_by_address": callees_by_address,
        "error":              None,
    }
