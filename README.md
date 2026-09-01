# Trivy GUI

Web UI for [Trivy](https://github.com/aquasecurity/trivy) image scans. Queue scans, compare results, rank CVEs by real-world exploitability (EPSS + CISA KEV), and keep an audit trail.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- Scan Docker images (vulnerabilities, optional secrets) including private registries
- Scan images of containers running on the host (`docker.sock`)
- Background job queue (one Trivy process at a time)
- Scan history with filters, bulk delete, ZIP export (JSON + CSV)
- Diff two finished scans of the same image: **new / fixed / unchanged** CVEs
- EPSS scores and CISA KEV flags; sort by exploitability, not only severity
- Exports: JSON, CSV, PDF (severity charts + EPSS/KEV columns)
- Dashboard: KPIs, timelines, posture, top images/CVEs/packages
- Roles: `user` (read/export), `manager` (scan/delete), `admin` (users, maintenance, audit)
- Audit log with CSV/JSON export
- UI in Polish and English
- Healthcheck, Trivy DB update, EPSS/KEV feed refresh, old-scan cleanup, SQLite VACUUM

## Deploy

**Requirements:** Docker + Compose, outbound HTTPS (Trivy DB, EPSS, CISA KEV).

```bash
git clone https://github.com/<you>/trivy-gui.git
cd trivy-gui
cp .env.example .env
docker compose up -d --build
```

Open `http://localhost:8086`.

### Environment

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | JWT secret (required in production) |
| `ADMIN_USER` | `admin` | Bootstrap admin login |
| `ADMIN_PASSWORD` | `admin123` | Bootstrap admin password — **change it** |
| `TOKEN_EXPIRE_MINUTES` | `120` | Session lifetime |

The first admin is created on startup and marked as protected (cannot be deleted). Password is **not** reset on later restarts.

### Volumes

- `trivy-cache` → Trivy CVE database cache
- `trivy-data` → SQLite (`/data/trivy_gui.db`)
- `/var/run/docker.sock` → list/scan local containers

### Example `docker-compose.yml`

```yaml
services:
  trivy-gui:
    build: .
    container_name: trivy-gui
    ports:
      - "8086:8000"
    environment:
      - SECRET_KEY=change-me
      - ADMIN_USER=admin
      - ADMIN_PASSWORD=change-me
      - TOKEN_EXPIRE_MINUTES=120
    volumes:
      - trivy-cache:/root/.cache/trivy
      - trivy-data:/data
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped

volumes:
  trivy-cache:
  trivy-data:
```

EPSS and CISA KEV feeds download in the background on first start (~24 h refresh). Force update from **Administration → Maintenance**.

## Usage

1. Log in as admin and create extra users if needed.
2. **Scans** — type an image (`nginx:latest`) or pick a host container.
3. Open a finished scan for details (KEV / EPSS sort). Export JSON / CSV / PDF.
4. Select **two finished scans of the same image** → **Compare**.
5. **Statistics** — 7 / 30 / 90 days or all time.
6. **Administration** (admin) — users, health, feeds, audit export.

## Roles

| Role | Access |
|---|---|
| `user` | View scans, containers, stats; download reports |
| `manager` | + start / delete scans |
| `admin` | + users, maintenance, audit log |

## API

JWT via `POST /api/login`. Main routes:

- `POST /api/scan`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/diff?a=&b=`
- `GET /api/scans/{id}/export/{json,csv,pdf}`
- `GET /api/stats`
- `GET /api/containers`
- `GET /api/audit`
- `GET /api/audit/export/{csv,json}`

Health probe (no auth): `GET /health`.

## Notes

- SQLite is fine for a single instance. Do not run multiple replicas on the same DB file.
- Mounting `docker.sock` gives the container access to the host Docker API — treat it as privileged.
- Set a strong `SECRET_KEY` and admin password before exposing the port.
