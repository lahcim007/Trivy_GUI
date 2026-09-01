import json
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, load_only
from .auth import get_current_user
from .database import get_db
from .epss import enrich_cves
from .models import Scan, User

router = APIRouter(prefix="/api", tags=["stats"])

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _period_filter(q, days: int):
    if days > 0:
        q = q.filter(Scan.created_at >= datetime.utcnow() - timedelta(days=days))
    return q


def _score(s: Scan) -> int:
    return (
        (s.critical or 0) * 10
        + (s.high or 0) * 5
        + (s.medium or 0) * 2
        + (s.low or 0)
        + (s.unknown or 0)
    )


def _trend(hist: list[Scan]) -> str:
    if len(hist) < 2:
        return "new"
    a, b = _score(hist[-2]), _score(hist[-1])
    if b < a:
        return "down"
    if b > a:
        return "up"
    return "stable"


@router.get("/stats")
def get_stats(days: int = Query(30, ge=0, le=3650),
              db: Session = Depends(get_db),
              _: User = Depends(get_current_user)):
    cols = load_only(
        Scan.id, Scan.image, Scan.status, Scan.created_at, Scan.finished_at,
        Scan.critical, Scan.high, Scan.medium, Scan.low, Scan.unknown,
        Scan.secrets_enabled, Scan.secrets_found,
    )
    scans = (
        _period_filter(db.query(Scan).options(cols), days)
        .order_by(Scan.created_at.asc())
        .all()
    )

    kpis = {
        "scans_total": len(scans),
        "scans_done": 0, "scans_error": 0, "scans_running": 0, "scans_pending": 0,
        "images_unique": 0, "clean_scans": 0, "secrets_scans": 0, "secrets_found": 0,
        "vulns_critical": 0, "vulns_high": 0, "vulns_medium": 0, "vulns_low": 0, "vulns_unknown": 0,
        "success_rate": 0, "avg_critical": 0, "avg_high": 0,
    }

    timeline_map: dict[str, dict] = {}
    by_image_all: dict[str, int] = defaultdict(int)
    hist: dict[str, list[Scan]] = defaultdict(list)

    for s in scans:
        st = s.status or "pending"
        if st in ("done", "error", "running", "pending"):
            kpis[f"scans_{st}"] += 1
        by_image_all[s.image] += 1

        day = s.created_at.strftime("%Y-%m-%d") if s.created_at else "unknown"
        bucket = timeline_map.setdefault(day, {
            "date": day, "scans": 0, "done": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "secrets": 0,
        })
        bucket["scans"] += 1

        if st == "done":
            bucket["done"] += 1
            bucket["critical"] += s.critical or 0
            bucket["high"] += s.high or 0
            bucket["medium"] += s.medium or 0
            bucket["low"] += s.low or 0
            bucket["unknown"] += s.unknown or 0
            bucket["secrets"] += s.secrets_found or 0
            kpis["vulns_critical"] += s.critical or 0
            kpis["vulns_high"] += s.high or 0
            kpis["vulns_medium"] += s.medium or 0
            kpis["vulns_low"] += s.low or 0
            kpis["vulns_unknown"] += s.unknown or 0
            if (s.critical or 0) + (s.high or 0) + (s.medium or 0) + (s.low or 0) == 0:
                kpis["clean_scans"] += 1
            hist[s.image].append(s)
            if s.secrets_enabled:
                kpis["secrets_scans"] += 1
                kpis["secrets_found"] += s.secrets_found or 0

    kpis["images_unique"] = len(by_image_all)
    finished = kpis["scans_done"] + kpis["scans_error"]
    kpis["success_rate"] = round(100 * kpis["scans_done"] / finished, 1) if finished else 0
    if kpis["scans_done"]:
        kpis["avg_critical"] = round(kpis["vulns_critical"] / kpis["scans_done"], 2)
        kpis["avg_high"] = round(kpis["vulns_high"] / kpis["scans_done"], 2)

    zeros = {
        "scans": 0, "done": 0, "critical": 0, "high": 0,
        "medium": 0, "low": 0, "unknown": 0, "secrets": 0,
    }
    if 0 < days <= 90:
        timeline = []
        cur = (datetime.utcnow() - timedelta(days=days)).date()
        end = datetime.utcnow().date()
        while cur <= end:
            key = cur.isoformat()
            timeline.append({"date": key, **timeline_map.get(key, zeros)})
            cur += timedelta(days=1)
    else:
        timeline = [timeline_map[k] for k in sorted(timeline_map)]

    latest = {img: rows[-1] for img, rows in hist.items()}
    posture = {
        "images": len(latest),
        "clean_images": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0,
        "secrets_found": 0, "risk_score": 0,
    }
    top_vulnerable = []
    for img, s in latest.items():
        posture["critical"] += s.critical or 0
        posture["high"] += s.high or 0
        posture["medium"] += s.medium or 0
        posture["low"] += s.low or 0
        posture["unknown"] += s.unknown or 0
        posture["secrets_found"] += s.secrets_found or 0
        if (s.critical or 0) + (s.high or 0) + (s.medium or 0) + (s.low or 0) == 0:
            posture["clean_images"] += 1
        top_vulnerable.append({
            "image": img,
            "status": "done",
            "critical": s.critical or 0,
            "high": s.high or 0,
            "medium": s.medium or 0,
            "low": s.low or 0,
            "unknown": s.unknown or 0,
            "secrets_found": s.secrets_found or 0,
            "last_id": s.id,
            "last_at": s.created_at.isoformat() if s.created_at else None,
            "scans": by_image_all.get(img, 0),
            "trend": _trend(hist[img]),
            "score": _score(s),
        })
    posture["risk_score"] = (
        posture["critical"] * 10 + posture["high"] * 5
        + posture["medium"] * 2 + posture["low"] + posture["unknown"]
    )
    top_vulnerable.sort(key=lambda x: (-x["critical"], -x["high"], -x["medium"], -x["score"]))
    top_vulnerable = top_vulnerable[:10]

    most_scanned = sorted(
        ({"image": img, "scans": n, "trend": _trend(hist[img]) if img in hist else "new",
          "score": _score(latest[img]) if img in latest else 0}
         for img, n in by_image_all.items()),
        key=lambda x: -x["scans"],
    )[:10]

    image_trends = []
    for img, rows in sorted(hist.items(), key=lambda kv: -len(kv[1])):
        if len(rows) < 2:
            continue
        image_trends.append({
            "image": img,
            "points": [
                {
                    "t": r.created_at.isoformat() if r.created_at else "",
                    "c": r.critical or 0, "h": r.high or 0,
                    "m": r.medium or 0, "l": r.low or 0,
                    "score": _score(r), "id": r.id,
                }
                for r in rows[-40:]
            ],
        })
        if len(image_trends) >= 6:
            break

    json_scans = (
        _period_filter(
            db.query(Scan)
            .options(load_only(Scan.image, Scan.result_json, Scan.created_at, Scan.status))
            .filter(Scan.status == "done", Scan.result_json.isnot(None)),
            days,
        )
        .order_by(Scan.created_at.desc())
        .limit(30)
        .all()
    )

    cve_map: dict[str, dict] = {}
    pkg_map: dict[str, dict] = {}
    for s in json_scans:
        try:
            report = json.loads(s.result_json or "{}")
        except json.JSONDecodeError:
            continue
        for res in report.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                cid = v.get("VulnerabilityID") or ""
                if not cid:
                    continue
                sev = v.get("Severity") or "UNKNOWN"
                rec = cve_map.setdefault(cid, {
                    "id": cid, "severity": sev,
                    "title": (v.get("Title") or "")[:160],
                    "pkg": v.get("PkgName") or "",
                    "count": 0, "images": set(),
                })
                rec["count"] += 1
                rec["images"].add(s.image)
                if SEV_RANK.get(sev, 9) < SEV_RANK.get(rec["severity"], 9):
                    rec["severity"] = sev
                    rec["pkg"] = v.get("PkgName") or rec["pkg"]
                    rec["title"] = (v.get("Title") or rec["title"])[:160]

                pkg = v.get("PkgName") or "unknown"
                p = pkg_map.setdefault(pkg, {
                    "name": pkg, "count": 0,
                    "critical": 0, "high": 0, "medium": 0, "low": 0,
                })
                p["count"] += 1
                key = sev.lower()
                if key in p:
                    p[key] += 1

    top_cves = []
    for rec in cve_map.values():
        top_cves.append({**rec, "images": len(rec["images"])})
    extra = enrich_cves(db, [x["id"] for x in top_cves])
    for x in top_cves:
        inf = extra.get(x["id"]) or {}
        x["epss"] = inf.get("epss")
        x["percentile"] = inf.get("percentile")
        x["kev"] = bool(inf.get("kev"))
        x["ransomware"] = inf.get("ransomware")
    top_cves.sort(key=lambda x: (
        0 if x.get("kev") else 1,
        -(x.get("epss") or 0),
        SEV_RANK.get(x["severity"], 9),
        -x["count"],
    ))
    top_packages = sorted(
        pkg_map.values(),
        key=lambda x: (-x["critical"], -x["high"], -x["count"]),
    )

    return {
        "period_days": days,
        "kpis": kpis,
        "posture": posture,
        "timeline": timeline,
        "top_vulnerable": top_vulnerable,
        "most_scanned": most_scanned,
        "image_trends": image_trends,
        "top_cves": top_cves[:15],
        "top_packages": top_packages[:15],
        "cves_sampled_scans": len(json_scans),
    }


@router.get("/stats/image")
def image_history(name: str = Query(..., min_length=1, max_length=512),
                  db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    rows = (
        db.query(Scan)
        .options(load_only(
            Scan.id, Scan.image, Scan.status, Scan.error, Scan.created_at, Scan.finished_at,
            Scan.critical, Scan.high, Scan.medium, Scan.low, Scan.unknown,
            Scan.secrets_enabled, Scan.secrets_found, Scan.created_by,
        ))
        .filter(Scan.image == name)
        .order_by(Scan.created_at.asc())
        .limit(100)
        .all()
    )
    if not rows:
        raise HTTPException(404, "Brak skanów dla tego obrazu")
    return {"image": name, "scans": [s.summary() for s in rows]}