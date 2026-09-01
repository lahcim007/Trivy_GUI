import docker
from fastapi import APIRouter, Depends, HTTPException, Query
from .auth import get_current_user
from .models import User

router = APIRouter(prefix="/api/containers", tags=["containers"])

def _client():
    try:
        return docker.from_env()
    except Exception as e:
        raise HTTPException(500, f"Brak połączenia z docker.sock: {e}")

def _human_size(n) -> str:
    if not n:
        return "0 B"
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def _extract_ips(attrs: dict) -> str:
    networks = attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
    parts = []
    for net_name, net_data in networks.items():
        ip = net_data.get("IPAddress")
        if ip:
            parts.append(f"{net_name}: {ip}")
    return ", ".join(parts) if parts else "—"

def _extract_ports(attrs: dict) -> str:
    ports = attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
    parts = []
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        for b in bindings:
            host_ip = b.get("HostIp") or "0.0.0.0"
            host_port = b.get("HostPort")
            if host_port:
                parts.append(f"{host_ip}:{host_port}->{container_port}")
    return ", ".join(parts) if parts else "—"

def _extract_stack(labels: dict) -> str:
    return (
        labels.get("com.docker.compose.project")
        or labels.get("com.docker.stack.namespace")
        or "—"
    )

def _extract_ownership(labels: dict) -> str:
    return labels.get("io.portainer.accesscontrol.owner") or "—"

@router.get("")
def list_containers(user: User = Depends(get_current_user)):
    client = _client()
    result = []
    for c in client.containers.list(all=True):
        attrs = c.attrs
        labels = attrs.get("Config", {}).get("Labels", {}) or {}
        try:
            image_tags = c.image.tags
            image = image_tags[0] if image_tags else c.image.short_id
        except Exception:
            image = "?"

        result.append({
            "id": c.short_id,
            "name": c.name,
            "image": image,
            "status": c.status,
            "stack": _extract_stack(labels),
            "created": attrs.get("Created"),
            "ip_address": _extract_ips(attrs),
            "ports": _extract_ports(attrs),
            "ownership": _extract_ownership(labels),
        })
    result.sort(key=lambda x: (x["status"] != "running", x["stack"], x["name"]))
    return result

@router.get("/{container_id}/size")
def container_size(container_id: str, user: User = Depends(get_current_user)):
    client = _client()
    try:
        matches = client.api.containers(all=True, size=True, filters={"id": [container_id]})
    except Exception as e:
        raise HTTPException(500, f"Nie udało się policzyć rozmiaru: {e}")

    if not matches:
        raise HTTPException(404, "Kontener nie znaleziony")

    raw = matches[0]
    size_rw = raw.get("SizeRw")
    size_root = raw.get("SizeRootFs")
    return {
        "size_rw": _human_size(size_rw),
        "size_root_fs": _human_size(size_root) if size_root else None,
    }

@router.get("/{container_id}/logs")
def container_logs(container_id: str, tail: int = Query(200, ge=10, le=5000),
                   user: User = Depends(get_current_user)):
    client = _client()
    try:
        c = client.containers.get(container_id)
    except docker.errors.NotFound:
        raise HTTPException(404, "Kontener nie znaleziony")
    raw = c.logs(tail=tail, timestamps=True, stdout=True, stderr=True)
    return {"logs": raw.decode("utf-8", errors="replace")}