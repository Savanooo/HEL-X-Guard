/*
 * HELİX-Guard Firmware YARA Ruleset
 * Version: 0.1.0
 *
 * Severity metadata values: "critical", "high", "medium", "low"
 * All rules use static pattern matching only — no dynamic execution.
 */

// ─────────────────────────────────────────────────────────────
// CRITICAL SEVERITY
// ─────────────────────────────────────────────────────────────

rule EmbeddedRSAPrivateKey
{
    meta:
        description = "RSA/EC/DSA/OpenSSH private key embedded in firmware"
        severity    = "critical"
        author      = "HELİX-Guard"

    strings:
        $begin_rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $begin_ec      = "-----BEGIN EC PRIVATE KEY-----"
        $begin_dsa     = "-----BEGIN DSA PRIVATE KEY-----"
        $begin_openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $begin_generic = "-----BEGIN PRIVATE KEY-----"

    condition:
        any of them
}

rule MiraiBotnet
{
    meta:
        description = "Mirai IoT botnet indicators"
        severity    = "critical"
        author      = "HELİX-Guard"

    strings:
        $s1 = "/bin/busybox MIRAI"   ascii
        $s2 = "hackforums"           ascii nocase
        $s3 = "/proc/net/tcp"        ascii
        $s4 = "BOTNET"               ascii nocase
        $s5 = "scanner.c"            ascii
        $s6 = { 72 6F 6F 74 00 78 63 33 65 6C 69 67 68 74 }

    condition:
        2 of them
}

rule EmbeddedSSHAuthorizedKey
{
    meta:
        description = "SSH public key in authorized_keys format embedded in firmware"
        severity    = "critical"
        author      = "HELİX-Guard"

    strings:
        $rsa_pub = "ssh-rsa AAAA"
        $ed25519 = "ssh-ed25519 AAAA"
        $ecdsa   = "ecdsa-sha2-nistp256 AAAA"

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// HIGH SEVERITY
// ─────────────────────────────────────────────────────────────

rule HardcodedDefaultCredentials
{
    meta:
        description = "Common default credentials hardcoded in firmware"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $c1  = "admin:admin"    ascii nocase
        $c2  = "root:root"      ascii nocase
        $c3  = "admin:password" ascii nocase
        $c4  = "root:toor"      ascii nocase
        $c5  = "admin:1234"     ascii nocase
        $c6  = "admin:12345"    ascii nocase
        $c7  = "admin:admin123" ascii nocase
        $c8  = "user:user"      ascii nocase
        $c9  = "guest:guest"    ascii nocase
        $c10 = "admin:pass"     ascii nocase
        $c11 = "admin\x00admin" ascii
        $c12 = "root\x00password" ascii

    condition:
        any of them
}

rule UPXPackedBinary
{
    meta:
        description = "UPX-packed executable detected — may conceal malicious payload"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $upx0     = "UPX0"          ascii
        $upx1     = "UPX1"          ascii
        $upx2     = "UPX2"          ascii
        $upx_magic = { 55 50 58 21 }

    condition:
        2 of them
}

rule AWSAccessKey
{
    meta:
        description = "AWS access key ID embedded in firmware"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $akia = /AKIA[0-9A-Z]{16}/
        $asia = /ASIA[0-9A-Z]{16}/

    condition:
        any of them
}

rule EmbeddedELFDropper
{
    meta:
        description = "ELF binary embedded within firmware image (possible dropper)"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $elf32_le = { 7F 45 4C 46 01 01 }
        $elf32_be = { 7F 45 4C 46 01 02 }
        $elf64_le = { 7F 45 4C 46 02 01 }
        $elf64_be = { 7F 45 4C 46 02 02 }

    condition:
        // ELF magic present but NOT at offset 0 (i.e., embedded within firmware)
        (any of them) and not (any of ($elf*) at 0)
}

rule SuspiciousDownloadChain
{
    meta:
        description = "wget/curl download chain pattern suggesting dropper behavior"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $w1 = /wget\s+https?:\/\/\S+\.sh/   ascii nocase
        $w2 = /curl\s+-[a-zA-Z]*o\s+\S+/    ascii nocase
        $w3 = /wget\s+-O\s*-\s+https?:/      ascii nocase
        $w4 = /curl\s+.*\|\s*(bash|sh)/      ascii nocase
        $w5 = /wget\s+.*\|\s*(bash|sh)/      ascii nocase

    condition:
        any of them
}

rule CryptoMiner
{
    meta:
        description = "Cryptocurrency mining strings embedded in firmware"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $m1 = "stratum+tcp://"          ascii nocase
        $m2 = "stratum+ssl://"          ascii nocase
        $m3 = "minerd"                  ascii nocase
        $m4 = "xmrig"                   ascii nocase
        $m5 = "cryptonight"             ascii nocase
        $m6 = "monero"                  ascii nocase
        $m7 = "donate.v2.xmrig.com"     ascii nocase

    condition:
        2 of them
}

// ─────────────────────────────────────────────────────────────
// MEDIUM SEVERITY
// ─────────────────────────────────────────────────────────────

rule BusyBoxEmbedded
{
    meta:
        description = "BusyBox embedded — indicates Linux environment in firmware"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $bb1       = "BusyBox v"                    ascii
        $bb2       = "busybox --install"             ascii nocase
        $bb3       = "/bin/busybox"                  ascii
        $bb_copy   = "BusyBox is free software"     ascii

    condition:
        any of them
}

rule TelnetBackdoor
{
    meta:
        description = "Telnet service enabled — insecure remote access vector"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $t1 = "telnetd"            ascii nocase
        $t2 = "/usr/sbin/telnetd"  ascii
        $t3 = "0.0.0.0:23"         ascii
        $t4 = "-p 23"              ascii

    condition:
        2 of them
}

rule EmbeddedInterpreter
{
    meta:
        description = "Embedded script interpreter binary present in firmware"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $python  = "/usr/bin/python"  ascii
        $python3 = "/usr/bin/python3" ascii
        $perl    = "/usr/bin/perl"    ascii
        $lua     = "/usr/bin/lua"     ascii
        $php     = "/usr/bin/php"     ascii
        $ruby    = "/usr/bin/ruby"    ascii

    condition:
        any of them
}

rule DebugBackdoorKeywords
{
    meta:
        description = "Debug backdoor or test-mode keywords embedded in firmware"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $d1 = "backdoor"      ascii nocase
        $d2 = "debug_mode"    ascii nocase
        $d3 = "test_mode"     ascii nocase
        $d4 = "ENABLE_DEBUG"  ascii
        $d5 = "factory_reset" ascii nocase
        $d6 = "secret_key"    ascii nocase
        $d7 = "HARDCODED"     ascii nocase

    condition:
        any of them
}

rule SuspiciousCronEntry
{
    meta:
        description = "Cron-style persistence mechanism strings"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $c1 = "/etc/cron"        ascii
        $c2 = "crontab -"        ascii
        $c3 = "* * * * *"        ascii
        $c4 = "/var/spool/cron"  ascii

    condition:
        2 of them
}

// ─────────────────────────────────────────────────────────────
// LOW SEVERITY
// ─────────────────────────────────────────────────────────────

rule GenericHTTPCommunication
{
    meta:
        description = "HTTP endpoints with raw IPs suggesting phone-home or C2 communication"
        severity    = "low"
        author      = "HELİX-Guard"

    strings:
        $h1 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii
        $h2 = "User-Agent:"    ascii
        $h3 = "Content-Type:"  ascii
        $h4 = "Authorization:" ascii

    condition:
        2 of them
}

rule Base64EncodedPayload
{
    meta:
        description = "Long base64 strings with padding that may encode embedded payloads"
        severity    = "low"
        author      = "HELİX-Guard"

    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={1,2}/

    condition:
        $b64
}

// ─────────────────────────────────────────────────────────────
// EMBEDDED / MCU FIRMWARE — NEW RULES
// ─────────────────────────────────────────────────────────────

rule FreeRTOSDetected
{
    meta:
        description = "FreeRTOS RTOS present — verify stack overflow protection and task isolation"
        severity    = "low"
        author      = "HELİX-Guard"

    strings:
        $s1 = "FreeRTOS"      ascii
        $s2 = "vTaskDelay"    ascii
        $s3 = "xTaskCreate"   ascii
        $s4 = "pvPortMalloc"  ascii
        $s5 = "xQueueCreate"  ascii
        $s6 = "heap_4.c"      ascii

    condition:
        2 of them
}

rule DebugLogFormatStrings
{
    meta:
        description = "Printf debug format strings reveal system internals — should be stripped in production"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $f1 = "[DEBUG]"   ascii nocase
        $f2 = "[INFO]"    ascii nocase
        $f3 = "[ERROR]"   ascii nocase
        $f4 = "[WARN]"    ascii nocase
        $f5 = "assert("   ascii
        $f6 = "%s:%d"     ascii
        $f7 = "=%d\n"     ascii
        $f8 = "=%s\n"     ascii

    condition:
        3 of them
}

rule WeakCryptographyIdentifiers
{
    meta:
        description = "Weak or deprecated cryptographic algorithm identifier strings"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $md5   = "MD5"         ascii
        $sha1  = "SHA-1"       ascii
        $des3  = "3DES"        ascii
        $rc4   = "RC4"         ascii nocase
        $ecb   = "_ECB_"       ascii
        $ecb2  = "ECB_Encrypt" ascii nocase
        $noaes = "no_encrypt"  ascii nocase

    condition:
        any of them
}

rule HardcodedNetworkConfig
{
    meta:
        description = "Hardcoded network configuration (private IPs, debug ports) embedded in firmware"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $ip1 = /192\.168\.\d{1,3}\.\d{1,3}/  ascii
        $ip2 = /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/  ascii
        $p1  = ":8080"   ascii
        $p2  = ":23"     ascii
        $p3  = ":4433"   ascii

    condition:
        any of ($ip*) or 2 of ($p*)
}

rule SerialConsoleInterface
{
    meta:
        description = "Serial/UART debug console interface strings — verify disabled in production"
        severity    = "medium"
        author      = "HELİX-Guard"

    strings:
        $c1 = "Command not found"  ascii nocase
        $c2 = "Invalid command"    ascii nocase
        $c3 = "Enter password"     ascii nocase
        $c4 = "login:"             ascii
        $c5 = "Password:"          ascii
        $c6 = "debug console"      ascii nocase
        $c7 = "boot>"              ascii nocase

    condition:
        any of them
}

rule FirmwareVersionString
{
    meta:
        description = "Embedded firmware version or build identifier string"
        severity    = "low"
        author      = "HELİX-Guard"

    strings:
        $v1 = /[Vv]ersion\s*[:\s]\s*\d+\.\d+/  ascii
        $v2 = /[Ff]irmware\s+[Vv]\d+\.\d+/     ascii
        $v3 = /SW\s*[Vv]er/                     ascii
        $v4 = /HW\s*[Vv]er/                     ascii

    condition:
        any of them
}

rule MedicalDeviceSensitiveStrings
{
    meta:
        description = "Medical device sensitive identifiers — verify patient data protection and regulatory compliance"
        severity    = "high"
        author      = "HELİX-Guard"

    strings:
        $m1 = "patient_id"   ascii nocase
        $m2 = "PATIENT_DATA" ascii
        $m3 = "HL7"          ascii
        $m4 = "DICOM"        ascii nocase
        $m5 = "serial_no"    ascii nocase
        $m6 = "calibration"  ascii nocase
        $m7 = "device_key"   ascii nocase

    condition:
        2 of them
}
