import gzip
import json
import threading
import urllib.request
from datetime import datetime, timedelta

from sqlalchemy import insert
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import EpssScore, FeedMeta, KevEntry

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_UA = {"User-Agent": "Mozilla/5.0 TrivyGUI"}
_feed_lock = threading.Lock()


def _download(url: str, timeout: int = 180) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _upsert_meta(db: Session, name: str, extra: str | None = None, error: bool = False):
    row = db.get(FeedMeta, name)
    if not row:
        row = FeedMeta(name=name)
        db.add(row)
    row.updated_at = datetime.utcnow()
    if extra:
        row.extra = (("błąd: " if error else "") + extra)[:256]
    else:
        row.extra = extra


def refresh_epss(db: Session):
    raw = _download(EPSS_URL)
    text_data = gzip.decompress(raw).decode("utf-8", errors="replace")
    db.query(EpssScore).delete()
    chunk = []
    n = 0
    for line in text_data.splitlines():
        if not line or line[0] == "#" or line.startswith("cve"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            chunk.append({
                "cve": parts[0][:32],
                "epss": float(parts[1]),
                "percentile": float(parts[2]),
            })
        except ValueError:
            continue
        if len(chunk) >= 500:
            db.execute(insert(EpssScore), chunk)
            n += len(chunk)
            chunk = []
    if chunk:
        db.execute(insert(EpssScore), chunk)
        n += len(chunk)
    _upsert_meta(db, "epss", extra=str(n))


def refresh_kev(db: Session):
    raw = _download(KEV_URL)
    data = json.loads(raw.decode("utf-8"))
    vulns = data.get("vulnerabilities") or []
    db.query(KevEntry).delete()
    batch = []
    n = 0
    for v in vulns:
        cve = (v.get("cveID") or "")[:32]
        if not cve:
            continue
        batch.append(KevEntry(
            cve=cve,
            vendor=(v.get("vendorProject") or "")[:256],
            product=(v.get("product") or "")[:256],
            name=(v.get("vulnerabilityName") or "")[:512],
            date_added=(v.get("dateAdded") or "")[:16],
            ransomware=(v.get("knownRansomwareCampaignUse") or "")[:32],
            due_date=(v.get("dueDate") or "")[:16],
        ))
        n += 1
        if len(batch) >= 500:
            db.add_all(batch)
            batch = []
    if batch:
        db.add_all(batch)
    _upsert_meta(db, "kev", extra=str(n))


def refresh_feeds():
    if not _feed_lock.acquire(blocking=False):
        return False
    db = SessionLocal()
    try:
        try:
            refresh_epss(db)
            db.commit()
        except Exception as e:
            db.rollback()
            _upsert_meta(db, "epss", extra=str(e)[:200], error=True)
            db.commit()
        try:
            refresh_kev(db)
            db.commit()
        except Exception as e:
            db.rollback()
            _upsert_meta(db, "kev", extra=str(e)[:200], error=True)
            db.commit()
        return True
    finally:
        db.close()
        _feed_lock.release()


def refresh_if_stale(max_age_hours: int = 24):
    db = SessionLocal()
    need = False
    try:
        now = datetime.utcnow()
        for name in ("epss", "kev"):
            row = db.get(FeedMeta, name)
            if not row or not row.updated_at:
                need = True
                break
            if now - row.updated_at > timedelta(hours=max_age_hours):
                need = True
                break
            if row.extra and str(row.extra).startswith("błąd"):
                need = True
                break
    finally:
        db.close()
    if need:
        refresh_feeds()


def startup_feeds():
    t = threading.Thread(target=refresh_if_stale, daemon=True)
    t.start()


def enrich_cves(db: Session, cve_ids: list[str]) -> dict:
    ids = []
    seen = set()
    for c in cve_ids:
        if c and c not in seen:
            seen.add(c)
            ids.append(c)
    out = {}
    if not ids:
        return out
    for i in range(0, len(ids), 800):
        chunk = ids[i:i + 800]
        emap = {r.cve: r for r in db.query(EpssScore).filter(EpssScore.cve.in_(chunk)).all()}
        kmap = {r.cve: r for r in db.query(KevEntry).filter(KevEntry.cve.in_(chunk)).all()}
        for c in chunk:
            e = emap.get(c)
            k = kmap.get(c)
            if not e and not k:
                continue
            out[c] = {
                "epss": e.epss if e else None,
                "percentile": e.percentile if e else None,
                "kev": bool(k),
                "kev_name": k.name if k else None,
                "vendor": k.vendor if k else None,
                "product": k.product if k else None,
                "date_added": k.date_added if k else None,
                "ransomware": k.ransomware if k else None,
                "due_date": k.due_date if k else None,
            }
    return out


def feed_status(db: Session) -> dict:
    def one(name):
        row = db.get(FeedMeta, name)
        if not row:
            return {"updated_at": None, "extra": None}
        return {
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "extra": row.extra,
        }
    return {
        "epss_feed": one("epss"),
        "kev_feed": one("kev"),
        "epss_rows": db.query(EpssScore).count(),
        "kev_rows": db.query(KevEntry).count(),
    }