# HELİX-Guard — Proje Yapısı

> Firmware binary statik güvenlik analiz platformu.  
> Backend: Python 3.11 + FastAPI · Frontend: Next.js 14 + TypeScript + TailwindCSS

---

## Dizin Ağacı

```
HELİX-Guard/
├── firmware-scanner/          ← Python backend (API + tarama motoru)
│   ├── api/                   ← FastAPI uygulaması
│   │   ├── routers/           ← Endpoint grupları
│   │   ├── templates/         ← PDF şablonu (Jinja2)
│   │   ├── main.py            ← FastAPI app, CORS, middleware
│   │   ├── models.py          ← SQLAlchemy ORM modelleri
│   │   ├── schemas.py         ← Pydantic request/response şemaları
│   │   ├── database.py        ← SQLite bağlantısı, session factory
│   │   ├── auth.py            ← JWT yardımcıları, password hash
│   │   ├── audit.py           ← Audit log yazıcı
│   │   ├── config.py          ← .env ile yapılandırma (pydantic-settings)
│   │   ├── storage.py         ← Dosya yükleme/indirme yardımcıları
│   │   ├── tasks.py           ← Arka plan tarama görevleri (thread)
│   │   ├── runner.py          ← Tarama motorunu çağıran orkestrasyonq
│   │   ├── celery_app.py      ← Opsiyonel Celery entegrasyonu
│   │   └── pdf_report.py      ← xhtml2pdf ile PDF rapor üretimi
│   │
│   ├── src/firmware_scanner/  ← Çekirdek tarama kütüphanesi (CLI + API ortak)
│   │   ├── hashing.py         ← MD5 / SHA-1 / SHA-256 (tek geçişte streaming)
│   │   ├── entropy.py         ← Shannon entropy analizi (blok + genel)
│   │   ├── strings_scan.py    ← ASCII + UTF-16 string çıkarımı, regex sınıflandırma
│   │   ├── yara_runner.py     ← YARA kural eşleştirme (yara-python)
│   │   ├── binwalk_runner.py  ← Binwalk imza tarama + güvenli extraction
│   │   ├── ghidra_runner.py   ← Ghidra headless decompile çalıştırıcı
│   │   ├── elf_analysis.py    ← ELF başlık / section / sembol analizi
│   │   ├── sandbox.py         ← Dosya işleme güvenlik kısıtlamaları
│   │   ├── risk_scoring.py    ← Ağırlıklı risk skoru hesaplama (0–100)
│   │   ├── report.py          ← JSON rapor oluşturma ve çıktı
│   │   └── cli.py             ← `firmware-scan` CLI komutu (Click)
│   │
│   ├── rules/
│   │   └── firmware_rules.yar ← 15 YARA kuralı (critical→low seviye)
│   │
│   ├── migrations/            ← Alembic veritabanı migration'ları
│   │   └── versions/
│   │       └── 0001_initial_schema.py
│   │
│   ├── tests/                 ← Pytest test suite
│   │   ├── conftest.py        ← Deterministik test binary fixture (seed=0xDEADBEEF)
│   │   ├── test_hashing.py
│   │   ├── test_entropy.py
│   │   ├── test_strings_scan.py
│   │   ├── test_yara_runner.py
│   │   ├── test_binwalk_runner.py
│   │   ├── test_ghidra_runner.py
│   │   ├── test_elf_analysis.py
│   │   ├── test_sandbox.py
│   │   ├── test_risk_scoring.py
│   │   └── test_report.py
│   │
│   ├── uploads/               ← Yüklenen firmware dosyaları (UUID.bin)
│   ├── outputs/               ← Extraction / decompile çıktıları (UUID/)
│   ├── .env                   ← Gizli yapılandırma (git'e eklenmez)
│   ├── .env.example           ← Şablon
│   ├── requirements-api.txt   ← API bağımlılıkları
│   ├── requirements.txt       ← CLI / tarama motoru bağımlılıkları
│   ├── pyproject.toml         ← Paket meta + entry point
│   ├── alembic.ini
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── helix-frontend/            ← Next.js 14 frontend (App Router)
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx         ← Root layout (metadata, globals.css)
│   │   │   ├── globals.css        ← CSS değişkenleri, body bg, scrollbar
│   │   │   ├── page.tsx           ← / → /dashboard yönlendirmesi
│   │   │   ├── login/
│   │   │   │   └── page.tsx       ← JWT login formu
│   │   │   └── dashboard/
│   │   │       ├── layout.tsx     ← Sidebar + header (JWT doğrulama)
│   │   │       ├── page.tsx       ← Tarama listesi + istatistik kartları
│   │   │       ├── upload/
│   │   │       │   └── page.tsx   ← Firmware yükleme (drag & drop)
│   │   │       ├── diff/
│   │   │       │   └── page.tsx   ← İki tarama karşılaştırma
│   │   │       ├── users/
│   │   │       │   └── page.tsx   ← Kullanıcı yönetimi (admin)
│   │   │       ├── audit/
│   │   │       │   └── page.tsx   ← Audit log görüntüleme (admin)
│   │   │       └── [scanId]/
│   │   │           └── page.tsx   ← Tarama detay sayfası (ana ekran)
│   │   │
│   │   ├── components/
│   │   │   ├── PipelineTree.tsx   ← 9 aşamalı L-bağlantılı analiz ağacı
│   │   │   ├── RiskBadge.tsx      ← Seviye rozeti (nokta + chip)
│   │   │   ├── RiskGauge.tsx      ← SVG yarım daire risk göstergesi
│   │   │   ├── StatusBadge.tsx    ← Tarama durumu rozeti
│   │   │   └── Spinner.tsx        ← Yükleme animasyonu
│   │   │
│   │   └── lib/
│   │       └── api.ts             ← Backend API istemcisi (fetch wrapper + tipler)
│   │
│   ├── tailwind.config.ts         ← Design token'lar (brand, hx, sev, shadow-card)
│   ├── next.config.mjs
│   ├── tsconfig.json
│   └── package.json
│
├── KURULUM.md                 ← Sunucu kurulum rehberi (Ubuntu 24.04)
├── YAPI.md                    ← Bu dosya
└── .gitignore
```

---

## Backend — `firmware-scanner/`

### API Katmanı (`api/`)

| Dosya | Sorumluluk |
|---|---|
| `main.py` | FastAPI app, CORS, lifespan, exception handler |
| `models.py` | `User`, `Scan`, `AuditLog` SQLAlchemy modelleri |
| `schemas.py` | Pydantic şemaları — `ScanCreate`, `ScanResponse`, `ScanDiffResponse`, vb. |
| `database.py` | SQLite engine, `SessionLocal`, `get_db` dependency |
| `auth.py` | `bcrypt` parola hash, `python-jose` JWT üretimi / doğrulama |
| `audit.py` | Tüm kritik işlemleri `AuditLog` tablosuna yazan yardımcı |
| `config.py` | `pydantic-settings` ile `.env` okuma (`SECRET_KEY`, `DB_PASSWORD`, vb.) |
| `storage.py` | `uploads/` ve `outputs/` dizini yönetimi |
| `tasks.py` | `threading.Thread` ile arka planda tarama çalıştırma |
| `runner.py` | Tüm tarama modüllerini sırayla çağıran pipeline orkestrasyonu |
| `pdf_report.py` | `xhtml2pdf` ile HTML→PDF dönüşümü, `report.html` şablonu |

### Router'lar (`api/routers/`)

| Router | Prefix | Önemli Endpoint'ler |
|---|---|---|
| `auth.py` | `/api/v1/auth` | `POST /login`, `GET /me`, `GET /users`, `POST /users` |
| `scans.py` | `/api/v1/scans` | `POST /` (yükle), `GET /`, `GET /{id}`, `DELETE /{id}`, `POST /{id}/extract`, `POST /{id}/decompile`, `GET /{id}/report.pdf`, `GET /{id_a}/diff/{id_b}` |
| `audit.py` | `/api/v1/audit` | `GET /` (sayfalı, filtreli) |

### Tarama Motoru (`src/firmware_scanner/`)

Analiz 9 aşamada çalışır — her modül bağımsız, hata yakalayan:

```
firmware binary
    │
    ├─ 1. hashing.py        → MD5 + SHA1 + SHA256 (streaming, 8 KB chunk)
    ├─ 2. entropy.py        → Genel + blok Shannon entropy (1 KB blok)
    ├─ 3. strings_scan.py   → ASCII/UTF-16 çıkarım + regex sınıflandırma
    │                          Kategoriler: PRIVATE_KEY, API_KEY, CREDENTIAL,
    │                          SAFETY_BYPASS, FLASH_WRITE, SHELL_COMMAND,
    │                          DEBUG_KEYWORD, CRYPTO, URL, IP, DOMAIN, VERSION
    ├─ 4. yara_runner.py    → 15 YARA kuralı eşleştirme (critical → low)
    ├─ 5. binwalk_runner.py → Gömülü imza tespiti (asla çalıştırmaz)
    ├─ 6. elf_analysis.py   → ELF başlık, section, sembol tablosu
    ├─ 7. ghidra_runner.py  → Headless Ghidra decompile (opsiyonel)
    ├─ 8. risk_scoring.py   → Ağırlıklı skor hesaplama (0–100)
    └─ 9. report.py         → JSON rapor çıktısı
```

### YARA Kuralları (`rules/firmware_rules.yar`)

| Kural | Seviye | Tetikleyici |
|---|---|---|
| `EmbeddedRSAPrivateKey` | critical | RSA/EC private key header |
| `MiraiBotnet` | critical | IoT botnet göstergeleri |
| `EmbeddedSSHAuthorizedKey` | critical | ssh-rsa / ed25519 public key |
| `HardcodedDefaultCredentials` | high | admin:admin, root:root |
| `UPXPackedBinary` | high | UPX0/UPX1 magic bytes |
| `AWSAccessKey` | high | AKIA* / ASIA* pattern |
| `EmbeddedELFInNonELF` | high | Offset > 0'da ELF magic |
| `SuspiciousDownloadChain` | high | wget/curl \| bash |
| `CryptoMiner` | high | stratum+tcp://, xmrig |
| `BusyBoxEmbedded` | medium | BusyBox version string |
| `TelnetBackdoor` | medium | telnetd + port 23 |
| `DebugBackdoorKeywords` | medium | backdoor, HARDCODED, test_mode |
| `SuspiciousCronEntry` | medium | /etc/cron + cron syntax |
| `GenericHTTPCommunication` | low | IP URL + HTTP header |
| `Base64EncodedPayload` | low | 100+ karakter base64 |

### Risk Skoru Ağırlıkları

| Faktör | Puan | Kap |
|---|---|---|
| YARA critical | +40 | — |
| YARA high | +20 | — |
| Private key bulgusu | +30 | tek seferlik |
| API key / credential | +20 / +8 | 25 |
| Yüksek entropy (>7.5) | +15 | — |
| Shell command | +5 | 15 |
| Debug keyword | +10 | 20 |
| YARA medium / low | +10 / +5 | — |

Eşikler: 0 = informational · 1–25 = low · 26–50 = medium · 51–75 = high · 76–100 = critical

---

## Frontend — `helix-frontend/`

### Sayfalar

| Route | Dosya | İçerik |
|---|---|---|
| `/login` | `login/page.tsx` | JWT giriş formu |
| `/dashboard` | `dashboard/page.tsx` | Tarama listesi, istatistik kartları, filtreler |
| `/dashboard/upload` | `upload/page.tsx` | Drag & drop firmware yükleme |
| `/dashboard/[scanId]` | `[scanId]/page.tsx` | Detay: Risk Gauge, Strings, YARA, Binwalk, Pipeline Tree, Decompile |
| `/dashboard/diff` | `diff/page.tsx` | İki tarama fark analizi |
| `/dashboard/users` | `users/page.tsx` | Kullanıcı oluşturma / listeleme (admin) |
| `/dashboard/audit` | `audit/page.tsx` | Audit log (admin) |

### Bileşenler

| Bileşen | Ne yapar |
|---|---|
| `PipelineTree` | 9 aşamalı analiz akışını L-bağlantılı ağaç olarak gösterir; severity filtre chip'leri, expand/collapse |
| `RiskBadge` | Seviye rozeti — renk + nokta göstergesi (critical=kırmızı, high=turuncu, medium=amber, low=yeşil, info=slate) |
| `RiskGauge` | SVG yarım daire göstergesi — skor ve seviyeye göre renklenir, koyu track |
| `StatusBadge` | Tarama durumu rozeti — running=amber+spinner, completed=yeşil, failed=kırmızı |
| `Spinner` | CSS animasyonlu yükleme çemberi |

### Design System

Tasarım tokenları `globals.css` CSS değişkenleri ve `tailwind.config.ts` içinde tanımlıdır:

```
Renkler
───────────────────────────────────────────────────
Arkaplan (bg)          #0b0f1a   ← en koyu, sayfa zemini
Surface (kartlar)      #121826   ← kart, sidebar
Surface-raised (modal) #161d2e   ← dropdown, modal
Border                 #1f2840   ← 1px kenar
Border-hover           #2d3a54   ← hover'da kenar

Brand (UI chrome)      #2563eb / #3b82f6 / #60a5fa
  Kullanım: logo, aktif nav, butonlar, linkler, odak halkası

Severity (içerik risk)
  CRITICAL             #ef4444   (kırmızı)
  HIGH                 #f97316   (turuncu)
  MEDIUM               #f59e0b   (amber)
  LOW / INFO           #64748b   (slate)
  ⚠ Severity rengi ASLA mavi değildir.

Yazı
  Birincil             #e2e8f0
  İkincil              #94a3b8
  Soluk                #64748b
  Mono (adres/hash)    JetBrains Mono
```

### API İstemcisi (`lib/api.ts`)

Tüm backend çağrıları bu modülden geçer:

- `getToken()` / `setToken()` / `clearToken()` — `localStorage` JWT yönetimi
- `req<T>(path, init)` — Authorization header ekleme, 401 → otomatik logout
- `listScans`, `getScan`, `createScan`, `deleteScan` — tarama CRUD
- `triggerExtract`, `triggerDecompile` — arka plan görev tetikleme
- `downloadReportPdf` — Bearer token ile PDF indirme (anchor yerine fetch)
- `diffScans(idA, idB)` — firmware karşılaştırma
- `listAuditLog`, `listUsers`, `createUser` — yönetim işlemleri

---

## Veritabanı Şeması

```
users
├── id          UUID PK
├── username    UNIQUE
├── email       UNIQUE
├── hashed_password
├── role        viewer | analyst | admin
├── is_active   boolean
└── created_at

scans
├── id                UUID PK
├── filename
├── file_size
├── sha256
├── status            pending | running | completed | failed
├── risk_score        0–100
├── risk_level        informational | low | medium | high | critical
├── report_json       ← tam tarama sonucu (JSON)
├── extraction_status pending | running | completed | failed | NULL
├── extraction_json
├── decompile_status  pending | running | completed | failed | NULL
├── decompile_json
├── created_at
└── completed_at

audit_logs
├── id            UUID PK
├── user_id       FK → users (nullable)
├── username      snapshot
├── action        login | create_scan | view_scan | delete_scan | ...
├── resource_type scan | user | ...
├── resource_id
├── success       boolean
├── detail        hata mesajı (opsiyonel)
├── ip_address
└── created_at
```

---

## Servisler (Üretim — Ubuntu 24.04)

```
systemd
├── helix-guard-api   → uvicorn api.main:app --port 8000
│                       Çalışma dizini: /root/HEL-X-Guard/firmware-scanner
│                       Python venv:    .venv/
│
└── helix-guard-ui    → next start --port 3000
                        Çalışma dizini: /root/HEL-X-Guard/helix-frontend
```

Nginx: `:80` → `:3000` (frontend) + `/api/` → `:8000` (backend proxy)

Sunucu: DigitalOcean Ubuntu 24.04 · IP: 134.209.226.25

---

## Güvenlik Prensipleri

- **Hiçbir dosya asla çalıştırılmaz** — extraction ve decompile yalnızca liste/analiz üretir
- **Tüm subprocess çağrıları** timeout + shell=False ile yapılır
- **Gizli bilgiler** (SECRET_KEY, DB_PASSWORD) yalnızca `.env` içinde, kod tabanında asla
- **JWT** — Bearer token, `python-jose`, 24 saatlik expiry
- **Parola** — `bcrypt` ile hash, minimum 8 karakter
- **Audit log** — tüm kimlik doğrulama, tarama ve yönetim işlemleri kayıt altında
- **CORS** — üretimde yalnızca frontend origin'e izin verilir
- **Rol tabanlı erişim** — `viewer/analyst/admin` hiyerarşisi, admin endpoint'leri korumalı

---

## Bağımlılıklar (Özet)

### Backend
```
fastapi · uvicorn · sqlalchemy · alembic · pydantic-settings
python-jose · passlib[bcrypt] · python-multipart
yara-python · xhtml2pdf · jinja2
```

### Frontend
```
next 14 · react 18 · typescript
tailwindcss · lucide-react
```

---

## Hızlı Komutlar

```bash
# Backend geliştirme
cd firmware-scanner
source .venv/bin/activate
uvicorn api.main:app --reload --port 8000

# CLI ile tek dosya tarama
firmware-scan firmware.bin --output report.json

# Test suite
pytest
pytest -m "not requires_binwalk"

# Frontend geliştirme
cd helix-frontend
npm run dev

# Üretim yeniden derleme (sunucuda)
cd helix-frontend && npm run build && systemctl restart helix-guard-ui
systemctl restart helix-guard-api

# Veritabanı migration
cd firmware-scanner
alembic upgrade head
```
