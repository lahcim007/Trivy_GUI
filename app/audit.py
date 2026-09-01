from .database import SessionLocal
from .models import AuditLog


def _client_ip(request) -> str | None:
    if request is None:
        return None
    xff = request.headers.get("x-forwarded-for") if request.headers else None
    if xff:
        return xff.split(",")[0].strip()[:64]
    if request.client and request.client.host:
        return request.client.host[:64]
    return None


def log_audit(username: str, action: str, target: str | None = None,
              details: str | None = None, request=None):
    db = SessionLocal()
    try:
        db.add(AuditLog(
            username=(username or "?")[:64],
            action=(action or "?")[:64],
            target=(target[:512] if target else None),
            details=details,
            ip=_client_ip(request),
        ))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()