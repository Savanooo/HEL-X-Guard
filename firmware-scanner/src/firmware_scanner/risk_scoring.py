from __future__ import annotations

# Scoring weights
W_HIGH_ENTROPY  = 15   # overall entropy > 7.5
W_CREDENTIAL    = 8    # per hardcoded credential finding
CAP_CREDENTIAL  = 25
W_PRIVATE_KEY   = 30   # one-time if any private key or certificate found
W_API_KEY       = 20   # per AWS/JWT/generic API key finding
CAP_API_KEY     = 40
W_SHELL_COMMAND = 5    # per shell command string
CAP_SHELL_CMD   = 15
W_DEBUG_KEYWORD = 10   # per debug/backdoor keyword
CAP_DEBUG       = 20

YARA_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high":     20,
    "medium":   10,
    "low":       5,
}

# ELF hardening mitigations — absence is a weak signal, not proof of compromise
W_ELF_NO_NX      = 5
W_ELF_NO_PIE     = 3
W_ELF_NO_CANARY  = 5
W_ELF_PARTIAL_RELRO = 2
W_ELF_NO_RELRO      = 4
CAP_ELF_HARDENING   = 15

SCORE_THRESHOLDS = [
    (76, 100, "critical"),
    (51, 75,  "high"),
    (26, 50,  "medium"),
    (1,  25,  "low"),
    (0,  0,   "informational"),
]


def _level(score: int) -> str:
    for lo, hi, level in SCORE_THRESHOLDS:
        if score >= lo:
            return level
    return "informational"


def score(
    entropy_result: dict,
    strings_result: dict,
    yara_result: dict,
    binwalk_result: dict | None = None,
    elf_result: dict | None = None,
) -> dict:
    """Compute a weighted risk score from all analysis module outputs.

    Returns:
        {"score": int, "level": str, "reasons": list[str]}
    """
    total = 0
    reasons: list[str] = []

    # ── Entropy ──────────────────────────────────────────────
    overall_entropy = entropy_result.get("overall", 0.0)
    if overall_entropy > 7.5:
        total += W_HIGH_ENTROPY
        reasons.append(
            f"High overall entropy ({overall_entropy:.2f}/8.00) — possible encryption or compression"
        )

    # ── String categories ─────────────────────────────────────
    categories: dict[str, int] = {}
    for item in strings_result.get("suspicious", []):
        cat = item.get("category", "")
        categories[cat] = categories.get(cat, 0) + 1

    if categories.get("PRIVATE_KEY", 0) + categories.get("CERTIFICATE", 0) > 0:
        total += W_PRIVATE_KEY
        reasons.append("Embedded private key or certificate detected")

    cred_count = categories.get("CREDENTIAL", 0)
    if cred_count > 0:
        contrib = min(cred_count * W_CREDENTIAL, CAP_CREDENTIAL)
        total += contrib
        reasons.append(
            f"Hardcoded credential strings found ({cred_count})"
        )

    api_count = categories.get("API_KEY", 0)
    if api_count > 0:
        contrib = min(api_count * W_API_KEY, CAP_API_KEY)
        total += contrib
        reasons.append(f"API key patterns detected ({api_count})")

    shell_count = categories.get("SHELL_COMMAND", 0)
    if shell_count > 0:
        contrib = min(shell_count * W_SHELL_COMMAND, CAP_SHELL_CMD)
        total += contrib
        reasons.append(f"Shell command strings embedded ({shell_count})")

    debug_count = categories.get("DEBUG_KEYWORD", 0)
    if debug_count > 0:
        contrib = min(debug_count * W_DEBUG_KEYWORD, CAP_DEBUG)
        total += contrib
        reasons.append(f"Debug/backdoor keywords found ({debug_count})")

    # ── YARA matches ─────────────────────────────────────────
    for match in yara_result.get("matches", []):
        severity = match.get("severity", "low")
        weight = YARA_WEIGHTS.get(severity, YARA_WEIGHTS["low"])
        total += weight
        reasons.append(
            f"YARA rule matched: {match.get('rule', 'unknown')} [{severity}]"
        )

    # ── ELF hardening mitigations ─────────────────────────────
    if elf_result and elf_result.get("is_elf") and not elf_result.get("error"):
        security = elf_result.get("security", {})
        elf_contrib = 0

        if not security.get("nx", True):
            elf_contrib += W_ELF_NO_NX
            reasons.append("ELF: NX (stack execution protection) disabled")
        if not security.get("pie", True):
            elf_contrib += W_ELF_NO_PIE
            reasons.append("ELF: not position-independent (no PIE)")

        relro = security.get("relro", "none")
        if relro == "none":
            elf_contrib += W_ELF_NO_RELRO
            reasons.append("ELF: no RELRO protection")
        elif relro == "partial":
            elf_contrib += W_ELF_PARTIAL_RELRO
            reasons.append("ELF: partial RELRO only")

        canary_present = "__stack_chk_fail" in (
            elf_result.get("imported_symbols", []) + elf_result.get("exported_symbols", [])
        )
        if not canary_present:
            elf_contrib += W_ELF_NO_CANARY
            reasons.append("ELF: no stack canary (__stack_chk_fail not linked)")

        total += min(elf_contrib, CAP_ELF_HARDENING)

    # Clamp to 0–100
    final_score = max(0, min(100, total))

    return {
        "score": final_score,
        "level": _level(final_score),
        "reasons": reasons,
    }
