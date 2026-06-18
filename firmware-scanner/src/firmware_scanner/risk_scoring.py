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
CAP_DEBUG       = 50   # raised: multiple safety-bypass flags each deserve contribution
W_CRYPTO        = 8    # per weak crypto identifier (MD5, DES, RC4 etc.)
CAP_CRYPTO      = 16
W_VERSION       = 0    # version strings are informational only
W_SAFETY_BYPASS = 20   # per safety-bypass flag (medical/embedded critical risk)
CAP_SAFETY      = 60
W_FLASH_WRITE   = 12   # per flash write/erase string
CAP_FLASH       = 24
W_WIFI_CRED     = 15   # hardcoded WiFi credentials
CAP_WIFI_CRED   = 15
W_MQTT_BROKER   = 5    # MQTT broker with embedded credentials
CAP_MQTT        = 10
W_BOOTLOADER    = 10   # bootloader bypass / DFU mode strings
CAP_BOOTLOADER  = 20

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

# checksec.py additional mitigations (lief-based)
W_CHECKSEC_NO_NX      = 5   # per missing mitigation, same scale as ELF above
W_CHECKSEC_NO_PIE     = 3
W_CHECKSEC_NO_CANARY  = 5
W_CHECKSEC_PARTIAL_RELRO = 2
W_CHECKSEC_NO_RELRO   = 4
CAP_CHECKSEC          = 15

# CVE matches (cve_match.py — Tier 2 opt-in)
W_CVE_CRITICAL  = 15   # per critical-severity CVE match
W_CVE_HIGH      = 8    # per high-severity CVE match
W_CVE_MEDIUM    = 3    # per medium
CAP_CVE         = 30   # cap across all CVE contributions

# Embedded certificate (cert_extract.py — Tier 3)
W_EMBEDDED_CERT = 5    # embedded X.509 cert is worth noting
CAP_CERT        = 5    # usually just one cert per firmware

# YARA bootloader/SWD-enable — extra weight for critical MCU rules
W_YARA_SWD_BOOTLOADER = 20  # applied on top of YARA_WEIGHTS for matching rules
_SWD_BOOTLOADER_RULES = frozenset({
    "STM32NoReadProtection",
    "UnsignedFirmwareUpdateBypass",
    "SWDJTAGEnable",
    "BootloaderUnlock",
})

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
    checksec_result: dict | None = None,
    cve_result: dict | None = None,
    cert_result: dict | None = None,
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
    # Use pre-computed category_counts if available (faster), else rebuild
    categories: dict[str, int] = strings_result.get("category_counts") or {}
    if not categories:
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

    crypto_count = categories.get("CRYPTO", 0)
    if crypto_count > 0:
        contrib = min(crypto_count * W_CRYPTO, CAP_CRYPTO)
        total += contrib
        reasons.append(f"Weak/deprecated cryptographic algorithm identifier(s) found ({crypto_count})")

    version_count = categories.get("VERSION", 0)
    if version_count > 0:
        reasons.append(f"Firmware version string(s) found ({version_count})")

    safety_count = categories.get("SAFETY_BYPASS", 0)
    if safety_count > 0:
        contrib = min(safety_count * W_SAFETY_BYPASS, CAP_SAFETY)
        total += contrib
        reasons.append(
            f"Safety-bypass or protection-disabled flag(s) found ({safety_count}) — patient-safety risk"
        )

    flash_count = categories.get("FLASH_WRITE", 0)
    if flash_count > 0:
        contrib = min(flash_count * W_FLASH_WRITE, CAP_FLASH)
        total += contrib
        reasons.append(f"Flash write/erase capability strings detected ({flash_count})")

    wifi_count = categories.get("WIFI_CREDENTIAL", 0)
    if wifi_count > 0:
        contrib = min(wifi_count * W_WIFI_CRED, CAP_WIFI_CRED)
        total += contrib
        reasons.append(f"Hardcoded WiFi credential(s) found ({wifi_count})")

    mqtt_count = categories.get("MQTT_BROKER", 0)
    if mqtt_count > 0:
        contrib = min(mqtt_count * W_MQTT_BROKER, CAP_MQTT)
        total += contrib
        reasons.append(f"MQTT broker string(s) with possible embedded credentials ({mqtt_count})")

    boot_count = categories.get("BOOTLOADER", 0)
    if boot_count > 0:
        contrib = min(boot_count * W_BOOTLOADER, CAP_BOOTLOADER)
        total += contrib
        reasons.append(f"Bootloader bypass / DFU-mode keyword(s) found ({boot_count})")

    # ── YARA matches ─────────────────────────────────────────
    for match in yara_result.get("matches", []):
        rule_name = match.get("rule", "unknown")
        severity  = match.get("severity", "low")
        weight    = YARA_WEIGHTS.get(severity, YARA_WEIGHTS["low"])
        if rule_name in _SWD_BOOTLOADER_RULES:
            weight = max(weight, W_YARA_SWD_BOOTLOADER)
        total += weight
        reasons.append(f"YARA rule matched: {rule_name} [{severity}]")

    # ── ELF hardening (elf_analysis.py) ──────────────────────
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

    # ── checksec.py (lief-based, overlaps with elf_analysis on ELF) ──────────
    if checksec_result and checksec_result.get("is_elf") and not checksec_result.get("error"):
        # Only apply if elf_analysis didn't already score this file
        if not (elf_result and elf_result.get("is_elf")):
            cs_contrib = 0
            if not checksec_result.get("nx", True):
                cs_contrib += W_CHECKSEC_NO_NX
                reasons.append("Checksec: NX disabled")
            if not checksec_result.get("pie", True):
                cs_contrib += W_CHECKSEC_NO_PIE
                reasons.append("Checksec: no PIE")
            relro = checksec_result.get("relro", "none")
            if relro == "none":
                cs_contrib += W_CHECKSEC_NO_RELRO
                reasons.append("Checksec: no RELRO")
            elif relro == "partial":
                cs_contrib += W_CHECKSEC_PARTIAL_RELRO
                reasons.append("Checksec: partial RELRO only")
            if not checksec_result.get("canary", True):
                cs_contrib += W_CHECKSEC_NO_CANARY
                reasons.append("Checksec: no stack canary")
            total += min(cs_contrib, CAP_CHECKSEC)

    # ── CVE matches (Tier 2 opt-in) ───────────────────────────
    if cve_result and not cve_result.get("error"):
        cve_contrib = 0
        sev_counts: dict[str, int] = {}
        for m in cve_result.get("matches", []):
            sev = m.get("severity", "medium").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev == "critical":
                cve_contrib += W_CVE_CRITICAL
            elif sev == "high":
                cve_contrib += W_CVE_HIGH
            else:
                cve_contrib += W_CVE_MEDIUM

        capped = min(cve_contrib, CAP_CVE)
        if capped > 0:
            total += capped
            parts = [f"{c} {s}" for s, c in sev_counts.items()]
            reasons.append(f"CVE match(es) in detected components: {', '.join(parts)}")

    # ── Embedded X.509 certificate (Tier 3 opt-in) ────────────
    if cert_result and not cert_result.get("error"):
        cert_count = cert_result.get("count", 0)
        if cert_count > 0:
            contrib = min(cert_count * W_EMBEDDED_CERT, CAP_CERT)
            total += contrib
            expired = sum(1 for c in cert_result.get("certificates", []) if c.get("is_expired"))
            msg = f"Embedded X.509 certificate(s) found ({cert_count})"
            if expired:
                msg += f" — {expired} expired"
            reasons.append(msg)

    # Clamp to 0–100
    final_score = max(0, min(100, total))

    return {
        "score":   final_score,
        "level":   _level(final_score),
        "reasons": reasons,
    }
