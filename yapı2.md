# HELİX-Guard — Tam Sistem Yapısı

> Son güncelleme: 2026-06-19  
> Durum: 179 test geçiyor, 25 skipped, 0 hata

---

## 1. Genel Mimari

```
HELİX-Guard/
├── firmware-scanner/          # Python backend (FastAPI + analiz motorları)
│   ├── api/                   # REST API katmanı
│   ├── src/firmware_scanner/  # Analiz modülleri (pip paketi)
│   ├── migrations/            # Alembic DB migration'ları
│   ├── rules/                 # YARA kuralları + CVE veritabanı
│   └── tests/                 # Pytest test suite (204 test)
└── helix-frontend/            # Next.js 14 frontend (TypeScript + Tailwind)
    └── src/
        ├── app/               # App Router sayfaları
        ├── components/        # Paylaşılan bileşenler
        └── lib/               # API istemcisi
```

**Teknoloji yığını:**
- Backend: Python 3.14 / FastAPI / SQLAlchemy / Alembic / SQLite (varsayılan)
- Frontend: Next.js 14.2 / React 18 / TypeScript / Tailwind CSS
- Tarayıcı: capstone (disasm), lief (checksec), yara-python (YARA), cryptography (sertifika)
- İsteğe bağlı: Docker sandbox, Celery + Redis, MinIO nesne deposu, Ghidra (decompile)

---

## 2. Veritabanı Şeması

### Tablo: `users`

| Sütun | Tip | Notlar |
|---|---|---|
| `id` | String(36) PK | UUID4 |
| `username` | String(64) UNIQUE | |
| `email` | String(256) UNIQUE | |
| `role` | String(16) | `admin` / `analyst` / `viewer` |
| `hashed_password` | String(256) | bcrypt |
| `is_active` | Boolean | |
| `failed_login_count` | Integer | Brute-force koruması |
| `locked_until` | DateTime nullable | Geçici kilit |
| `created_at` | DateTime | |

### Tablo: `scans`

| Sütun | Tip | Notlar |
|---|---|---|
| `id` | String(36) PK | UUID4 |
| `user_id` | String(36) FK → users | |
| `filename` | String(256) | |
| `file_size` | Integer nullable | |
| `sha256` | String(64) nullable | |
| `stored_path` | String(512) nullable | Yerel yol veya MinIO anahtar |
| `status` | String(16) | pending/running/completed/failed |
| `risk_score` | Float nullable | 0–100 |
| `risk_level` | String(16) nullable | informational/low/medium/high/critical |
| `report_json` | Text nullable | Tier 1 tam rapor (JSON) |
| `error_message` | Text nullable | |
| `extraction_status` | String(16) nullable | Tier 1 derin analiz: binwalk |
| `extraction_json` | Text nullable | |
| `extraction_error` | Text nullable | |
| `decompile_status` | String(16) nullable | İsteğe bağlı: Ghidra |
| `decompile_json` | Text nullable | |
| `decompile_error` | Text nullable | |
| `cve_status` | String(16) nullable | Tier 2: CVE eşleştirme |
| `cve_json` | Text nullable | |
| `cve_error` | Text nullable | |
| `disasm_status` | String(16) nullable | Tier 2: Talimat histogramı |
| `disasm_json` | Text nullable | |
| `disasm_error` | Text nullable | |
| `created_at` | DateTime | |
| `completed_at` | DateTime nullable | |

### Tablo: `audit_log`

| Sütun | Tip | Notlar |
|---|---|---|
| `id` | String(36) PK | |
| `user_id` | String(36) nullable | |
| `username` | String(64) nullable | |
| `action` | String(64) | create_scan, delete_scan, trigger_cve… |
| `resource_type` | String(32) nullable | scan, user |
| `resource_id` | String(36) nullable | |
| `success` | Boolean | |
| `detail` | Text nullable | |
| `ip_address` | String(64) nullable | |
| `created_at` | DateTime | |

### Migration geçmişi

| Revizyon | İçerik |
|---|---|
| `0001` | Temel şema: users, scans, audit_log |
| `0002` | Tier 2 sütunları: cve_*, disasm_* (6 sütun) |

---

## 3. API Uç Noktaları

Taban URL: `/api/v1`

### Kimlik Doğrulama (`/auth`)

| Metot | Yol | Yetki | Açıklama |
|---|---|---|---|
| POST | `/auth/login` | Herkese açık | JWT token al (form-data) |
| GET | `/auth/me` | viewer+ | Mevcut kullanıcı bilgisi |
| GET | `/auth/users` | admin | Tüm kullanıcıları listele |
| POST | `/auth/users` | admin | Yeni kullanıcı oluştur |

### Taramalar (`/scans`)

| Metot | Yol | Yetki | Açıklama |
|---|---|---|---|
| POST | `/scans` | analyst+ | Firmware yükle, Tier 1 analizi başlat |
| GET | `/scans` | viewer+ | Sayfalı liste (filtre: risk_level, status) |
| GET | `/scans/{id}` | viewer+ | Tam rapor dahil tarama detayı |
| DELETE | `/scans/{id}` | viewer+ | Tarama ve dosyayı sil |
| POST | `/scans/{id}/extract` | analyst+ | Binwalk çıkarma başlat |
| POST | `/scans/{id}/decompile` | analyst+ | Ghidra decompile başlat |
| POST | `/scans/{id}/analyze/cve` | analyst+ | Tier 2: CVE eşleştirme başlat |
| POST | `/scans/{id}/analyze/disasm` | analyst+ | Tier 2: Talimat histogramı başlat |
| GET | `/scans/{id}/diff/{id2}` | viewer+ | İki tarama arasındaki fark |
| GET | `/scans/{id}/report.pdf` | viewer+ | PDF rapor indir |

### Denetim Günlüğü (`/audit`)

| Metot | Yol | Yetki | Açıklama |
|---|---|---|---|
| GET | `/audit` | admin | Sayfalı audit log (filtre: action, username) |

---

## 4. Analiz Modülleri

### Tier 1 — Her taramada otomatik çalışır

| Modül | Dosya | Çıktı |
|---|---|---|
| **Hashing** | `hashing.py` | MD5, SHA1, SHA256 |
| **Entropy** | `entropy.py` | Genel entropi, 1KB blok histogramı, yorum |
| **Strings** | `strings_scan.py` | ASCII + UTF-16LE tarama, 19 kategori, regex sınıflandırma |
| **Binwalk** | `binwalk_runner.py` | Gömülü dosya imzaları (tarama modu) |
| **YARA** | `yara_runner.py` | Kural eşleştirme, severity metadata |
| **ELF Analiz** | `elf_analysis.py` | Sütun türü, bölümler, semboller, import'lar |
| **Arch Detect** | `arch_detect.py` | CPU mimarisi, endianness, vektör tablosu, reset handler disasm |
| **Checksec** | `checksec.py` | NX, PIE, stack canary, RELRO, FORTIFY (lief tabanlı) |
| **Crypto Sabitler** | `crypto_constants.py` | Gömülü kriptografik sabitler (AES S-box, MD5 init vb.) |
| **Bileşenler** | `components.py` | SBOM — FreeRTOS, OpenSSL, BusyBox, lwIP, Zephyr tespiti |
| **Sertifika** | `cert_extract.py` | Gömülü X.509 sertifikaları (PEM + DER) |
| **Risk Puanlama** | `risk_scoring.py` | 0-100 puan, 5 seviye (tüm modülleri bir araya getirir) |
| **Rapor** | `report.py` | Canonical JSON rapor; PDF için html template |

### Tier 2 — İsteğe bağlı, POST ile tetiklenir

| Modül | Dosya | Tetikleyici | Açıklama |
|---|---|---|---|
| **CVE Eşleştirme** | `cve_match.py` | POST `/analyze/cve` | SBOM'u offline `cve_db.json`'a göre eşler (34 kayıt) |
| **Disasm İstatistik** | `disasm_stats.py` | POST `/analyze/disasm` | Capstone Thumb-2 taraması; talimat histogramı, fonksiyon prolog sayımı |

### İsteğe Bağlı — Ağır araçlar

| Modül | Dosya | Koşul | Açıklama |
|---|---|---|---|
| **Ghidra** | `ghidra_runner.py` | GHIDRA_HOME env var | Headless decompile; pseudocode per function |
| **Docker Sandbox** | `sandbox.py` | HELIX_USE_DOCKER_SANDBOX=true | İzole tarama ortamı |

---

## 5. Strings Kategorileri ve Risk Ağırlıkları

| Kategori | Ağırlık | Cap | Açıklama |
|---|---|---|---|
| `PRIVATE_KEY` | 30 (tek seferlik) | — | RSA/EC/DSA/OPENSSH özel anahtar başlığı |
| `CERTIFICATE` | 30 (tek seferlik) | — | X.509 sertifika başlığı |
| `API_KEY` | 20/bulgu | 40 | AKIA*, JWT, 40+ hex char, base64 padded |
| `WIFI_CREDENTIAL` | 15/bulgu | 15 | ssid=, wpa_passphrase= vb. |
| `CREDENTIAL` | 8/bulgu | 25 | password=, secret=, token= vb. |
| `SAFETY_BYPASS` | 20/bulgu | 60 | no_water_test, DISABLE_MPU, RDP_BYPASS |
| `FLASH_WRITE` | 12/bulgu | 24 | FLASH_Unlock, xtx_erase_sector |
| `DEBUG_KEYWORD` | 10/bulgu | 50 | backdoor, DFU_MODE, semihosting |
| `BOOTLOADER` | 10/bulgu | 20 | DFU_MODE, IAP_*, Jump_To_Application |
| `MQTT_BROKER` | 5/bulgu | 10 | mqtt://, port 1883/8883 |
| `SHELL_COMMAND` | 5/bulgu | 15 | wget, bash -c, chmod |
| `URL` | — | — | http/https URL'ler |
| `IP` | — | — | IPv4 adresleri |
| `DOMAIN` | — | — | Bilinen TLD'li alan adları |
| `NETWORK_SERVICE` | — | — | telnet, ftp, ssh + port |
| `AT_COMMAND` | — | — | AT+CWJAP, AT+CIPSTART vb. |
| `FILE_PATH` | — | — | /etc/, /proc/, /tmp/ yolları |
| `CRYPTO` | 8/bulgu | 16 | MD5, RC4, DES, AES-128 zayıf kripto |
| `VERSION` | 0 | — | Sürüm string'leri (bilgi amaçlı) |

**Öncelik sırası** (`_CATEGORY_PRIORITY`):
`PRIVATE_KEY` → `CERTIFICATE` → `API_KEY` → `WIFI_CREDENTIAL` → `CREDENTIAL` → `URL` → `IP` → `DOMAIN` → `SHELL_COMMAND` → `MQTT_BROKER` → `AT_COMMAND` → `BOOTLOADER` → `SAFETY_BYPASS` → `FLASH_WRITE` → `DEBUG_KEYWORD` → `NETWORK_SERVICE` → `FILE_PATH` → `CRYPTO` → `VERSION`

---

## 6. YARA Kuralları (`rules/firmware_rules.yar`)

| Kural | Seviye | Tetikleyici |
|---|---|---|
| `EmbeddedRSAPrivateKey` | critical | BEGIN PRIVATE KEY başlıkları |
| `MiraiBotnet` | critical | Mirai IoT botnet göstergeleri |
| `EmbeddedSSHAuthorizedKey` | critical | ssh-rsa/ed25519 public key |
| `WeakCryptographyIdentifiers` | high | MD5, RC4, DES kullanımı |
| `HardcodedDefaultCredentials` | high | admin:admin, root:root |
| `UPXPackedBinary` | high | UPX0/UPX1 magic bytes |
| `AWSAccessKey` | high | AKIA*/ASIA* pattern |
| `EmbeddedELFDropper` | high | Offset dışı gömülü ELF |
| `SuspiciousDownloadChain` | high | wget/curl pipe to bash |
| `CryptoMiner` | high | stratum+tcp://, xmrig |
| `BusyBoxEmbedded` | medium | BusyBox v* string |
| `TelnetBackdoor` | medium | telnetd + port 23 |
| `EmbeddedInterpreter` | medium | Python/Perl/Lua embedding |
| `DebugBackdoorKeywords` | medium | backdoor, HARDCODED, test_mode |
| `SuspiciousCronEntry` | medium | /etc/cron + * * * * * |
| `HardcodedNetworkConfig` | medium | Sabit IP + port kombinasyonu |
| `DebugLogFormatStrings` | medium | printf/semihosting debug çıktıları |
| `FreeRTOSDetected` | low | FreeRTOS v* string |
| `GenericHTTPCommunication` | low | IP URL + HTTP header |
| `Base64EncodedPayload` | low | 100+ karakter base64 |

**YARA Risk Ağırlıkları:** critical=40, high=20, medium=10, low=5

---

## 7. CVE Veritabanı (`rules/cve_db.json`)

34 CVE kaydı. Her kayıt:
```json
{
  "cve_id": "CVE-2018-16522",
  "component": "FreeRTOS",
  "affected_versions": ["<=10.0.1", "10.0.0", "10.0.1"],
  "cvss": 10.0,
  "severity": "critical",
  "summary": "..."
}
```

CVE Risk Ağırlıkları: critical=15/eşleşme, high=8, medium=3 | Cap=30

---

## 8. Disasm İstatistikleri (`disasm_stats.py`)

- **Mod:** Sadece Thumb-2 (Cortex-M, Thumb-only)
- **Motor:** capstone `Cs(CS_ARCH_ARM, CS_MODE_THUMB)` + `skipdata=True`
- **Çıktı:**
  ```json
  {
    "available": true,
    "mode": "thumb",
    "load_address": "0x8000000",
    "code_bytes": 2097152,
    "total_instructions": 183402,
    "function_prologues": 4218,
    "branch_instructions": 22100,
    "memory_instructions": 61500,
    "suspicious": {"bkpt": 0, "svc": 12, "udf": 0},
    "top_mnemonics": [{"mnemonic": "ldr", "count": 31200}, ...]
  }
  ```
- **Mnemonic normalizasyonu:** `.w`/`.n` suffix'leri kırpılır; koşullu dallar collapse edilir (`beq`→`b`, `bleq`→`bl`)
- **Fonksiyon prolog:** `PUSH {…, lr}` sayısı (yaklaşık)

---

## 9. Arch Detect Çıktısı

```json
{
  "arch": "ARM",
  "endianness": "little",
  "is_bare_metal": true,
  "inferred_load_address": "0x8000000",
  "initial_sp": "0x20020000",
  "reset_handler": "0x8000149",
  "sp_in_ram": true,
  "thumb_mode": true,
  "vector_table": [
    {"index": 0, "raw": "0x20020000", "addr": "0x20020000", "thumb": false},
    {"index": 1, "raw": "0x08000149", "addr": "0x8000148", "thumb": true}
  ],
  "reset_disasm": [
    "0x8000148: push {r3, lr}",
    "0x800014a: bl 0x80001f0"
  ],
  "error": null
}
```

---

## 10. Risk Puanlama Eşikleri

| Puan | Seviye |
|---|---|
| 76–100 | critical |
| 51–75 | high |
| 26–50 | medium |
| 1–25 | low |
| 0 | informational |

---

## 11. Arka Plan İş Akışı

```
POST /scans
  └─► dispatch_scan()
        └─► _run_scan() [daemon thread]
              ├─ Tier 1 modülleri sırayla çalışır
              └─ report_json, risk_score DB'ye yazılır

POST /scans/{id}/extract
  └─► dispatch_extraction() → _run_extraction() → binwalk.extract()

POST /scans/{id}/decompile
  └─► dispatch_decompile() → _run_decompile() → ghidra_runner.decompile()

POST /scans/{id}/analyze/cve
  └─► dispatch_cve() → _run_cve_match() → cve_match.match()

POST /scans/{id}/analyze/disasm
  └─► dispatch_disasm() → _run_disasm() → disasm_stats.analyze()
```

Celery etkinleştirildiğinde (`HELIX_USE_CELERY=true`) thread'ler yerine Celery görevleri kullanılır.

---

## 12. Konfigürasyon (`.env` / ortam değişkenleri)

Tüm değişkenler `HELIX_` önekiyle tanımlanır:

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `HELIX_SECRET_KEY` | `CHANGE_ME_...` | JWT imzalama anahtarı |
| `HELIX_DATABASE_URL` | `sqlite:///./helix.db` | SQLAlchemy URL |
| `HELIX_UPLOAD_DIR` | `./uploads` | Firmware dosyaları |
| `HELIX_MAX_FILE_SIZE` | `524288000` | 500 MB |
| `HELIX_SCAN_TIMEOUT` | `300` | Saniye |
| `HELIX_USE_DOCKER_SANDBOX` | `false` | Docker izolasyonu |
| `HELIX_USE_CELERY` | `false` | Async iş kuyruğu |
| `HELIX_REDIS_URL` | `redis://localhost:6379/0` | Celery broker |
| `HELIX_USE_OBJECT_STORAGE` | `false` | MinIO kullan |
| `HELIX_MINIO_ENDPOINT` | `localhost:9000` | |
| `HELIX_ADMIN_USERNAME` | `admin` | Bootstrap admin |
| `HELIX_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT TTL |

---

## 13. Frontend Sayfaları ve Bileşenleri

### Sayfalar (`/helix-frontend/src/app/`)

| Yol | Dosya | Açıklama |
|---|---|---|
| `/` | `app/page.tsx` | Yönlendirme (login → dashboard) |
| `/login` | `app/login/page.tsx` | JWT giriş formu |
| `/dashboard` | `app/dashboard/page.tsx` | Tarama listesi, filtre, risk badge'leri |
| `/dashboard/upload` | `app/dashboard/upload/page.tsx` | Firmware yükleme + canlı polling |
| `/dashboard/[scanId]` | `app/dashboard/[scanId]/page.tsx` | Tarama detay (7 sekme + Tier 2 paneller) |
| `/dashboard/diff` | `app/dashboard/diff/page.tsx` | İki tarama karşılaştırması |
| `/dashboard/audit` | `app/dashboard/audit/page.tsx` | Audit log tablosu |
| `/dashboard/users` | `app/dashboard/users/page.tsx` | Kullanıcı yönetimi (admin) |

### Tarama Detay Sekmeleri

| Sekme | İçerik |
|---|---|
| **Strings** | Kategorilere göre renklendirilmiş şüpheli string'ler; 19 kategori badge |
| **YARA** | Kural eşleşmeleri, severity badge, string offsets |
| **Binwalk** | Gömülü dosya imzaları tablosu |
| **Tree** | Çıkarılan dosya ağacı (extraction_json) |
| **Arch** | Mimari bilgisi, vektör tablosu, reset handler disasm |
| **SBOM** | Tespit edilen yazılım bileşenleri (components.py çıktısı) |
| **Crypto** | Gömülü kriptografik sabitler (crypto_constants.py) |

### Tier 2 Derin Analiz Panelleri (sekme altında)

| Panel | Tetikleyici | Gösterilen bilgi |
|---|---|---|
| **CVE Match** | "Run CVE Match" butonu | Eşleşen CVE'ler, CVSS, component versiyon |
| **Disasm Stats** | "Run Disasm Stats" butonu | Talimat sayısı, fonksiyon prolog tahmini, mnemonic bar chart |

### Paylaşılan Bileşenler

| Bileşen | Dosya | Açıklama |
|---|---|---|
| `RiskBadge` | `components/RiskBadge.tsx` | Renkli risk seviyesi badge |
| `RiskGauge` | `components/RiskGauge.tsx` | 0-100 arc gauge |
| `StatusBadge` | `components/StatusBadge.tsx` | pending/running/completed/failed badge |
| `Spinner` | `components/Spinner.tsx` | Yükleme animasyonu |
| `PipelineTree` | `components/PipelineTree.tsx` | Binwalk çıkarma ağacı |
| `TabErrorBoundary` | `dashboard/[scanId]/page.tsx` | React class error boundary (sekme çökmesi yalıtımı) |
| `ArchPanel` | `dashboard/[scanId]/page.tsx` | Arch sekmesi function component |
| `DisasmResults` | `dashboard/[scanId]/page.tsx` | Disasm Stats görselleştirme |

### API İstemcisi (`/helix-frontend/src/lib/api.ts`)

Tüm endpoint'ler için fonksiyonlar: `login`, `getMe`, `createScan`, `listScans`, `getScan`, `deleteScan`, `triggerExtract`, `triggerDecompile`, `triggerCve`, `triggerDisasm`, `diffScans`, `downloadReportPdf`, `listAuditLog`

---

## 14. Test Suite

**Çalıştırma:** `cd firmware-scanner && pytest`  
**Sonuç:** 179 geçti, 25 skipped (capstone/yara-python olmadan), 0 hata

| Test dosyası | Test sayısı | Notlar |
|---|---|---|
| `test_arch_detect.py` | 15 | lief mevcut değilse bazıları skip |
| `test_binwalk_runner.py` | 10 | |
| `test_checksec.py` | 9 | 1 skip |
| `test_components.py` | 13 | |
| `test_crypto_constants.py` | 14 | |
| `test_disasm_stats.py` | 27 | 21 skip (capstone yok) |
| `test_elf_analysis.py` | 23 | |
| `test_entropy.py` | 14 | |
| `test_ghidra_runner.py` | 9 | Mock tabanlı, Ghidra gerekmez |
| `test_hashing.py` | 7 | |
| `test_report.py` | 11 | |
| `test_risk_scoring.py` | 16 | |
| `test_sandbox.py` | 13 | |
| `test_strings_scan.py` | 14 | |
| `test_yara_runner.py` | 9 | 3 skip (yara-python yok) |

**Skip sebepleri:**
- `requires_capstone` — capstone paketi yüklü değil
- `requires_yara` — yara-python paketi yüklü değil  
- `requires_lief` — lief paketi yüklü değil (Windows geliştirme ortamında)

---

## 15. Dağıtım Mimarisi (Üretim)

```
Nginx (443 SSL)
├── /api/v1/*    → uvicorn :8000  (FastAPI)
└── /*           → Next.js :3000 (systemd: helix-guard-ui)

SQLite: /root/HEL-X-Guard/firmware-scanner/helix.db
Uploads: /root/HEL-X-Guard/firmware-scanner/uploads/
```

**Servis dosyası:** `systemctl restart helix-guard-ui`  
**Build:** `cd helix-frontend && npm run build && systemctl restart helix-guard-ui`  
**Güncelleme:** `git pull --no-rebase --no-edit && cd helix-frontend && npm run build && systemctl restart helix-guard-ui`

---

## 16. Güvenlik Özellikleri

- JWT Bearer token kimlik doğrulama (RS256 / HS256)
- Rol tabanlı erişim kontrolü: `admin > analyst > viewer`
- Brute-force koruması: başarısız giriş sayacı + geçici hesap kilidi
- Yükleme kısıtlamaları: izin verilen uzantılar, 500 MB dosya boyutu sınırı
- Firmware hiçbir zaman çalıştırılmaz — tüm analiz statik
- Audit log: tüm kritik işlemler IP adresi ile kayıt altına alınır
- Docker sandbox seçeneği: ağ erişimi olmayan izole konteyner taraması
