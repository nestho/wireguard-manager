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
