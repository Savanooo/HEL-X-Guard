# HELİX-Guard — Kurulum ve Proje Yapısı

Firmware/binary dosyalarını statik olarak analiz eden, risk skorlayan ve raporlayan
güvenlik platformu. 9 fazlık bir mimariyle geliştirildi: CLI tarama motoru → ELF
analizi → Docker sandbox → FastAPI → Celery/Redis → PostgreSQL/MinIO → PDF rapor →
Next.js arayüz → Audit/RBAC.

> **Güvenlik notu:** Hiçbir extracted dosya veya firmware binary'si otomatik
> çalıştırılmaz. Binwalk extraction ve Ghidra decompile dahil tüm analizler
> statiktir.

---

## 1. Proje Yapısı

```
HELİX-Guard/
├── firmware-scanner/                  # Python backend (CLI + FastAPI)
│   ├── src/firmware_scanner/          # Faz 1-2: statik analiz motoru (pip paketi)
│   │   ├── hashing.py                 # MD5/SHA1/SHA256 streaming hash
│   │   ├── entropy.py                 # Shannon entropy (overall + blok bazlı)
│   │   ├── strings_scan.py            # ASCII/UTF-16 string çıkarımı + kategorizasyon
│   │   ├── binwalk_runner.py          # binwalk scan/extract wrapper
│   │   ├── yara_runner.py             # YARA kural motoru wrapper
│   │   ├── elf_analysis.py            # ELF header/section/security analizi
│   │   ├── ghidra_runner.py           # Ghidra headless decompile wrapper (opsiyonel)
│   │   ├── risk_scoring.py            # Ağırlıklı risk skoru (0-100)
│   │   ├── report.py                  # JSON rapor birleştirme
│   │   ├── sandbox.py                 # Faz 3: Docker container izolasyonu
│   │   └── cli.py                     # `firmware-scan` komut satırı arayüzü
│   │
│   ├── api/                           # Faz 4-9: FastAPI servis katmanı
│   │   ├── main.py                    # Uygulama girişi, Alembic migration bootstrap
│   │   ├── config.py                  # Tüm ayarlar (pydantic-settings, .env)
│   │   ├── database.py                # SQLAlchemy engine/session
│   │   ├── models.py                  # User, Scan, AuditLog ORM modelleri
│   │   ├── schemas.py                 # Pydantic request/response şemaları
│   │   ├── auth.py                    # JWT, bcrypt, RBAC, brute-force kilitleme
│   │   ├── audit.py                   # Audit log yazma yardımcı modülü
│   │   ├── storage.py                 # Faz 6: local disk / MinIO depolama katmanı
│   │   ├── runner.py                  # Tarama yürütme (thread veya Celery dispatch)
│   │   ├── tasks.py                   # Faz 5: Celery task tanımları
│   │   ├── celery_app.py              # Celery uygulama yapılandırması
│   │   ├── pdf_report.py              # Faz 7: PDF rapor render (xhtml2pdf)
│   │   ├── templates/report.html      # PDF rapor HTML şablonu
│   │   └── routers/
│   │       ├── auth.py                # /api/v1/auth/* (login, users)
│   │       ├── scans.py               # /api/v1/scans/* (CRUD, extract, decompile, pdf)
│   │       └── audit.py               # /api/v1/audit (admin-only log görüntüleme)
│   │
│   ├── migrations/                    # Faz 6: Alembic şema versiyonlama
│   │   ├── env.py
│   │   └── versions/0001_initial_schema.py
│   │
│   ├── rules/firmware_rules.yar       # 15 YARA kuralı (kötü amaçlı/zayıf imzalar)
│   ├── tests/                         # pytest test suite (126 test)
│   ├── Dockerfile                     # Sandbox scanner image (Faz 3)
│   ├── docker-compose.yml             # Sandbox container tanımı
│   ├── docker-compose.dev.yml         # Redis + PostgreSQL + MinIO (Faz 5/6 altyapısı)
│   ├── alembic.ini
│   ├── pyproject.toml                 # firmware_scanner paket tanımı
│   ├── requirements.txt               # CLI bağımlılıkları
│   ├── requirements-api.txt           # API bağımlılıkları
│   └── .env.example                   # Tüm ortam değişkenleri şablonu
│
├── helix-frontend/                    # Faz 8: Next.js arayüz
│   ├── src/
│   │   ├── app/
│   │   │   ├── login/                 # Giriş sayfası
│   │   │   └── dashboard/
│   │   │       ├── page.tsx           # Tarama listesi (filtre, sayfalama)
│   │   │       ├── upload/            # Firmware yükleme (drag-drop)
│   │   │       ├── [scanId]/          # Tarama detayı (risk, bulgular, extract/decompile, PDF)
│   │   │       ├── users/             # Kullanıcı yönetimi (admin)
│   │   │       └── audit/             # Audit log görüntüleme (admin)
│   │   ├── components/                # RiskBadge, RiskGauge, StatusBadge, Spinner
│   │   └── lib/api.ts                 # Backend API istemcisi
│   ├── package.json
│   └── .env.local.example
│
└── .gitignore
```

---

## 2. Gereksinimler

| Bileşen | Zorunlu mu? | Not |
|---|---|---|
| Python 3.10+ | ✅ | Backend için |
| Node.js 18+ | ✅ | Frontend için |
| Docker Desktop | ❌ opsiyonel | Sandbox izolasyon, Redis/PostgreSQL/MinIO altyapısı için |
| binwalk | ❌ opsiyonel | Yoksa zarif hata ile devam eder |
| yara-python | ❌ opsiyonel | Python 3.13+ Windows'ta wheel sorunlu olabilir |
| Ghidra | ❌ opsiyonel | Decompile özelliği için, `GHIDRA_HOME` ile etkinleşir |

---

## 3. Backend Kurulumu (firmware-scanner)

### 3.1 CLI tarama motoru

```powershell
cd firmware-scanner
pip install -e .
pip install -e ".[dev]"   # testler için

# Kullanım
firmware-scan firmware.bin --output report.json
firmware-scan firmware.bin --extract --rules rules/firmware_rules.yar

# Test
pytest
```

### 3.2 FastAPI servis katmanı

```powershell
cd firmware-scanner
pip install -r requirements-api.txt
Copy-Item .env.example .env
```

`.env` dosyasını düzenle (özellikle `HELIX_SECRET_KEY`, `HELIX_ADMIN_PASSWORD`).

```powershell
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

İlk başlatmada:
- Alembic migration'ları otomatik uygulanır (`alembic upgrade head`)
- Varsayılan admin kullanıcı oluşturulur (`.env`'deki `HELIX_ADMIN_USERNAME` / `HELIX_ADMIN_PASSWORD`)

Swagger UI: **http://127.0.0.1:8000/docs**

---

## 4. Opsiyonel Altyapı (Docker)

Tüm destekleyici servisler tek dosyada:

```powershell
cd firmware-scanner
docker compose -f docker-compose.dev.yml up -d
```

Bu şu servisleri başlatır:

| Servis | Port | Amaç |
|---|---|---|
| Redis | 6379 | Faz 5 — Celery job queue broker |
| PostgreSQL | 5432 | Faz 6 — production veritabanı |
| MinIO | 9000 (API), 9001 (konsol) | Faz 6 — S3-uyumlu obje depolama |

### 4.1 Async job queue (Celery + Redis)

`.env`:
```
HELIX_USE_CELERY=true
HELIX_REDIS_URL=redis://localhost:6379/0
```

Worker başlat (Windows'ta `--pool=solo` zorunlu):
```powershell
celery -A api.celery_app worker --loglevel=info --pool=solo
```

### 4.2 PostgreSQL

`.env`:
```
HELIX_DATABASE_URL=postgresql+psycopg://helix:helix@localhost:5432/helixdb
```
API yeniden başlatıldığında migration'lar otomatik uygulanır — manuel adım gerekmez.

### 4.3 MinIO (obje depolama)

`.env`:
```
HELIX_USE_OBJECT_STORAGE=true
HELIX_MINIO_ENDPOINT=localhost:9000
HELIX_MINIO_ACCESS_KEY=helixadmin
HELIX_MINIO_SECRET_KEY=helixsecret
```
Konsol: **http://localhost:9001**

### 4.4 Docker sandbox (izole tarama)

```powershell
docker build -t helix-guard-scanner:latest .
```
`.env`:
```
HELIX_USE_DOCKER_SANDBOX=true
```
Her tarama `--network none --read-only` gibi kısıtlamalarla ayrı bir container'da çalışır.

### 4.5 Ghidra decompile (opsiyonel)

```
GHIDRA_HOME=C:\path\to\ghidra
```
Tanımlı değilse `/decompile` endpoint'i `501 Not Implemented` döner (zarif hata).

---

## 5. Frontend Kurulumu (helix-frontend)

```powershell
cd helix-frontend
npm install
Copy-Item .env.local.example .env.local
npm run dev
```

Tarayıcı: **http://localhost:3000** → giriş bilgisi backend'deki admin hesabı.

---

## 6. Hızlı Doğrulama

```powershell
# Backend testleri
cd firmware-scanner
pytest

# Frontend tip kontrolü
cd helix-frontend
npx tsc --noEmit
npm run build
```

---

## 7. API Endpoint Özeti

| Metot | Yol | Yetki |
|---|---|---|
| `POST` | `/api/v1/auth/login` | — |
| `GET` | `/api/v1/auth/me` | herhangi bir kullanıcı |
| `POST`/`GET` | `/api/v1/auth/users` | admin |
| `POST` | `/api/v1/scans` | analyst/admin |
| `GET` | `/api/v1/scans` | herhangi bir kullanıcı |
| `GET`/`DELETE` | `/api/v1/scans/{id}` | sahip/admin |
| `GET` | `/api/v1/scans/{id}/report` | sahip/admin |
| `GET` | `/api/v1/scans/{id}/report.pdf` | sahip/admin |
| `POST` | `/api/v1/scans/{id}/extract` | analyst/admin |
| `POST` | `/api/v1/scans/{id}/decompile` | analyst/admin |
| `GET` | `/api/v1/audit` | admin |
