import csv
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from io import StringIO
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, Scan, AuditLog
from .auth import get_current_user, require_admin, hash_password
from .scanner import submit_job
from .audit import log_audit
from .epss import feed_status, refresh_feeds

router = APIRouter(prefix="/api", tags=["admin"])


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user.summary()


class PasswordChange(BaseModel):
    password: str


@router.put("/me/password")
def change_my_password(req: PasswordChange, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    if len(req.password) < 6:
        raise HTTPException(400, "Hasło musi mieć min. 6 znaków")
    user.password_hash = hash_password(req.password)
    db.commit()
    log_audit(user.username, "password_change", request=request)
    return {"ok": True}


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return [u.summary() for u in db.query(User).order_by(User.id).all()]


@router.post("/users")
def create_user(req: UserCreate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    if req.role not in ("admin", "manager", "user"):
        raise HTTPException(400, "Rola musi być 'admin', 'manager' lub 'user'")
    if len(req.password) < 6:
        raise HTTPException(400, "Hasło musi mieć min. 6 znaków")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Taki użytkownik już istnieje")
    db.add(User(username=req.username, password_hash=hash_password(req.password), role=req.role))
    db.commit()
    log_audit(admin.username, "user_create", req.username, details=f"role={req.role}", request=request)
    return {"ok": True}


@router.put("/users/{user_id}/password")
def admin_set_password(user_id: int, req: PasswordChange, request: Request,
                       db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono użytkownika")
    if len(req.password) < 6:
        raise HTTPException(400, "Hasło musi mieć min. 6 znaków")
    target.password_hash = hash_password(req.password)
    db.commit()
    log_audit(admin.username, "user_password_set", target.username, request=request)
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db),
                current: User = Depends(require_admin)):
    if user_id == current.id:
        raise HTTPException(400, "Nie możesz usunąć samego siebie")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Nie znaleziono użytkownika")
    if target.is_protected:
        raise HTTPException(400, "To konto jest chronione (root) i nie można go usunąć")
    if target.role == "admin" and db.query(User).filter(User.role == "admin").count() <= 1:
        raise HTTPException(400, "Nie można usunąć ostatniego administratora")
    uname = target.username
    db.delete(target)
    db.commit()
    log_audit(current.username, "user_delete", uname, request=request)
    return {"ok": True}


@router.get("/health")
def health(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    info = {}
    try:
        v = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=10)
        info["trivy"] = v.stdout.strip().splitlines()[0] if v.returncode == 0 else v.stderr.strip()
    except Exception as e:
        info["trivy"] = f"błąd: {e}"

    try:
        import docker
        docker.from_env().ping()
        info["docker_socket"] = "OK"
    except Exception as e:
        info["docker_socket"] = f"błąd: {e}"

    try:
        db.execute(text("SELECT 1"))
        info["database"] = "OK"
    except Exception as e:
        info["database"] = f"błąd: {e}"

    try:
        _, _, free = shutil.disk_usage("/data")
        info["disk_data_free_mb"] = round(free / (1024 * 1024))
    except Exception:
        info["disk_data_free_mb"] = None

    try:
        _, _, free_cache = shutil.disk_usage("/root/.cache/trivy")
        info["disk_cache_free_mb"] = round(free_cache / (1024 * 1024))
    except Exception:
        info["disk_cache_free_mb"] = None

    info["scans_total"] = db.query(Scan).count()
    info["scans_running"] = db.query(Scan).filter(Scan.status == "running").count()
    info.update(feed_status(db))
    return info


def _audit_query(db: Session, action: str | None, username: str | None):
    q = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        q = q.filter(AuditLog.action == action)
    if username:
        q = q.filter(AuditLog.username == username)
    return q


@router.get("/audit")
def list_audit(page: int = Query(1, ge=1),
               per_page: int = Query(40, ge=10, le=200),
               action: str | None = Query(None),
               username: str | None = Query(None),
               db: Session = Depends(get_db),
               _: User = Depends(require_admin)):
    q = _audit_query(db, action, username)
    total = q.count()
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "items": [r.summary() for r in rows],
    }


@router.get("/audit/export/csv")
def export_audit_csv(request: Request,
                     action: str | None = Query(None),
                     username: str | None = Query(None),
                     db: Session = Depends(get_db),
                     admin: User = Depends(require_admin)):
    rows = _audit_query(db, action, username).limit(20000).all()
    buf = StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow(["Data_UTC", "Uzytkownik", "Akcja", "Cel", "Szczegoly", "IP"])
    for r in rows:
        w.writerow([
            r.created_at.isoformat() if r.created_at else "",
            r.username or "",
            r.action or "",
            r.target or "",
            r.details or "",
            r.ip or "",
        ])
    log_audit(admin.username, "export_audit_csv",
              details=f"count={len(rows)}" + (f", action={action}" if action else "") + (f", user={username}" if username else ""),
              request=request)
    return Response(buf.getvalue().encode("utf-8-sig"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="trivy_audit.csv"'})


@router.get("/audit/export/json")
def export_audit_json(request: Request,
                      action: str | None = Query(None),
                      username: str | None = Query(None),
                      db: Session = Depends(get_db),
                      admin: User = Depends(require_admin)):
    import json
    rows = _audit_query(db, action, username).limit(20000).all()
    payload = json.dumps([r.summary() for r in rows], ensure_ascii=False, indent=2)
    log_audit(admin.username, "export_audit_json",
              details=f"count={len(rows)}" + (f", action={action}" if action else "") + (f", user={username}" if username else ""),
              request=request)
    return Response(payload.encode("utf-8"), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="trivy_audit.json"'})


@router.post("/maintenance/update-db")
def update_vuln_db(request: Request, admin: User = Depends(require_admin)):
    def _job():
        subprocess.run(["trivy", "image", "--download-db-only"],
                       capture_output=True, text=True, timeout=1800)
    submit_job(_job)
    log_audit(admin.username, "db_update", request=request)
    return {"ok": True, "message": "Aktualizacja bazy CVE dodana do kolejki (wykona się po bieżących skanach)"}


@router.post("/maintenance/update-feeds")
def update_feeds(request: Request, admin: User = Depends(require_admin)):
    submit_job(refresh_feeds)
    log_audit(admin.username, "feeds_update", request=request)
    return {"ok": True, "message": "Aktualizacja EPSS/KEV dodana do kolejki"}


@router.post("/maintenance/cleanup")
def cleanup_old_scans(request: Request, days: int = 30, db: Session = Depends(get_db),
                      admin: User = Depends(require_admin)):
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted = db.query(Scan).filter(Scan.created_at < cutoff).delete()
    db.commit()
    log_audit(admin.username, "scans_cleanup", details=f"days={days}, deleted={deleted}", request=request)
    return {"ok": True, "deleted": deleted}


@router.post("/maintenance/vacuum")
def vacuum_db(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    db.execute(text("VACUUM"))
    log_audit(admin.username, "db_vacuum", request=request)
    return {"ok": True}