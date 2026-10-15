"""Guarded peer lifecycle endpoints. Mutations require dry-run preview followed by explicit confirmation."""
import base64, ipaddress, json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .audit import record_event
from .db import get_db
from .dependencies import current_user, require_roles
from .models import Peer, Router, User
from .routeros import RouterOSClient, RouterConnectionError
from .schemas import PeerCreate
from .security import encrypt_secret
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

router = APIRouter(prefix="/api/v1/routers/{router_id}/peers", tags=["peers"])
def generate_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(private_raw).decode(), base64.b64encode(public_raw).decode()

def validate_address(value: str) -> str:
    try:
        network = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise HTTPException(422, "allowed_address must be a valid IP interface, e.g. 10.20.0.2/32") from exc
    if network.ip.is_loopback or network.ip.is_link_local or network.ip.is_multicast or network.ip.is_unspecified:
        raise HTTPException(422, "Loopback, link-local, multicast and unspecified peer addresses are not allowed")
    if network.version == 4 and network.network.prefixlen < 24:
        raise HTTPException(422, "Peer IPv4 address must use a /24 through /32 prefix; avoid broad routes")
    if network.version == 6 and network.network.prefixlen < 64:
        raise HTTPException(422, "Peer IPv6 address must use a /64 through /128 prefix; avoid broad routes")
    return str(network)

@router.post("/preview")
def preview_peer(router_id: int, body: PeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    address = validate_address(body.allowed_address)
    collision = db.query(Peer).filter(Peer.router_id == router_id, Peer.allowed_address == address, Peer.status != "revoked").first()
    if collision:
        raise HTTPException(409, "Address is already allocated in the local inventory")
    return {"dry_run": True, "router_id": router_id, "name": body.name, "allowed_address": address, "will_create_router_peer": True, "will_store_private_key_encrypted": True, "requires_explicit_confirmation": True, "warning": "This preview does not reserve the address and does not check all router-side conflicts."}

@router.post("")
async def create_peer(router_id: int, body: PeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    if body.dry_run or not body.confirm:
        raise HTTPException(409, "Mutation blocked: first review /preview, then send dry_run=false and confirm=true")
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    address = validate_address(body.allowed_address)
    if db.query(Peer).filter(Peer.router_id == router_id, Peer.allowed_address == address, Peer.status != "revoked").first():
        raise HTTPException(409, "Address is already allocated in the local inventory")
    private_key, public_key = generate_keypair()
    try:
        client = RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)
        # The account must be scoped to the required WireGuard resources. RouterOS
        # permissions cannot be safely inferred here, so deployment must use a
        # dedicated account and an explicit allow-list at the router/firewall.
        response = await client.get("/interface/wireguard")
        if not response:
            raise RouterConnectionError("No WireGuard interface configured")
        interfaces = response if isinstance(response, list) else [response]
        interface = next((x for x in interfaces if x.get("running") in (True, "true", "yes")), interfaces[0])
        interface_id = interface.get(".id")
        if not interface_id:
            raise RouterConnectionError("RouterOS did not return interface identifier")
        # Mutating methods are intentionally absent from the REST client in this milestone.
        raise HTTPException(501, "Peer mutation adapter is not enabled until router-side rollback and address-pool reconciliation are verified")
    except RouterConnectionError:
        record_event(db, user.username, "peer.create", "router", str(router_id), outcome="failed", details={"reason": "router_preflight_failed"})
        db.commit()
        raise HTTPException(502, "Router preflight failed; no peer was created")
