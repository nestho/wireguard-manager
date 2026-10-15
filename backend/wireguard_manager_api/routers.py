"""Router registration and read-only inventory endpoints."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .audit import record_event
from .db import get_db
from .dependencies import current_user, require_roles
from .models import Router, User
from .routeros import RouterOSClient, RouterConnectionError, validate_router_host
from .schemas import RouterCreate
from .security import encrypt_secret

router = APIRouter(prefix="/api/v1/routers", tags=["routers"])

def client_for(item: Router) -> RouterOSClient:
    return RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)

def view(item: Router) -> dict:
    return {"id": item.id, "name": item.name, "host": item.host, "port": item.port, "username": item.username, "tls_verify": item.tls_verify, "last_status": item.last_status, "created_at": item.created_at.isoformat()}

@router.get("")
def list_routers(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [view(x) for x in db.query(Router).order_by(Router.id.desc()).all()]

@router.post("", status_code=201)
def add_router(body: RouterCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    try:
        host = validate_router_host(body.host)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    item = Router(name=body.name, host=host, port=body.port, username=body.username, credential_ciphertext=encrypt_secret(body.password), tls_verify=body.tls_verify, last_status="unverified")
    db.add(item)
    db.flush()
    record_event(db, user.username, "router.register", "router", str(item.id), details={"host": host, "port": body.port})
    db.commit()
    return view(item)

@router.post("/{router_id}/test")
async def test_router(router_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    try:
        resource = await client_for(item).get("/system/resource")
        identity = await client_for(item).get("/system/identity")
        item.last_status = "healthy"
        result = {"status": "healthy", "identity": identity, "resource": resource}
        record_event(db, user.username, "router.connection_test", "router", str(item.id), details={"outcome": "success"})
    except RouterConnectionError:
        item.last_status = "unreachable"
        record_event(db, user.username, "router.connection_test", "router", str(item.id), outcome="failed", details={"reason": "connection_failed"})
        db.commit()
        raise HTTPException(502, "Router connection failed; credentials and internal network details are not returned")
    item.last_check_at = datetime.now(timezone.utc)
    db.commit()
    return result

@router.get("/{router_id}/wireguard/peers")
async def read_peers(router_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    try:
        peers = await client_for(item).get("/interface/wireguard/peers")
        interfaces = await client_for(item).get("/interface/wireguard")
    except RouterConnectionError:
        raise HTTPException(502, "Unable to read WireGuard inventory from router")
    return {"router_id": item.id, "interfaces": interfaces, "peers": peers, "read_only": True, "retrieved_at": datetime.now(timezone.utc).isoformat()}


@router.get("/{router_id}/traffic")
async def live_traffic(router_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Read current RouterOS peer counters; values are point-in-time, not historical analytics."""
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    try:
        raw = await client_for(item).get("/interface/wireguard/peers")
    except RouterConnectionError:
        raise HTTPException(502, "Unable to collect traffic counters from router")
    peers = raw if isinstance(raw, list) else [raw]
    collected_at = datetime.now(timezone.utc).isoformat()
    result = []
    for peer in peers:
        result.append({
            "router_peer_id": peer.get(".id"),
            "name": peer.get("name") or peer.get("comment") or peer.get("public-key", "unknown")[:12],
            "public_key": peer.get("public-key"),
            "allowed_address": peer.get("allowed-address"),
            "rx_bytes": int(peer.get("rx", 0) or 0),
            "tx_bytes": int(peer.get("tx", 0) or 0),
            "last_handshake": peer.get("last-handshake"),
            "disabled": str(peer.get("disabled", "false")).lower() == "true",
            "collected_at": collected_at,
        })
    record_event(db, user.username, "router.traffic_read", "router", str(item.id), details={"peer_count": len(result)})
    db.commit()
    return {"router_id": item.id, "collected_at": collected_at, "historical": False, "peers": result}

@router.get("/{router_id}/diagnostics")
async def router_diagnostics(router_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    """Run a bounded set of read-only checks against a registered router."""
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    checks = []
    client = client_for(item)
    for name, path in (
        ("system_resource", "/system/resource"),
        ("system_identity", "/system/identity"),
        ("wireguard_interfaces", "/interface/wireguard"),
        ("wireguard_peers", "/interface/wireguard/peers"),
    ):
        started = datetime.now(timezone.utc)
        try:
            value = await client.get(path)
            count = len(value) if isinstance(value, list) else 1
            checks.append({"name": name, "status": "ok", "item_count": count, "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000)})
        except RouterConnectionError:
            checks.append({"name": name, "status": "failed", "item_count": None, "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000)})
            break
    overall = "healthy" if all(check["status"] == "ok" for check in checks) else "degraded"
    item.last_status = overall
    item.last_check_at = datetime.now(timezone.utc)
    record_event(db, user.username, "router.diagnostics", "router", str(item.id), outcome="success" if overall == "healthy" else "warning", details={"checks": checks})
    db.commit()
    return {"router_id": item.id, "status": overall, "checked_at": item.last_check_at.isoformat(), "checks": checks, "read_only": True}
