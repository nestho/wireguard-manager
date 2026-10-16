"""Guarded peer lifecycle endpoints: dry-run, explicit confirmation, and rollback."""
import base64
import ipaddress
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from .access_control import normalize_networks, routeros_rule_plan\nfrom .audit import record_event
from .config import get_settings
from .db import get_db
from .dependencies import current_user, require_roles
from .models import Peer, Router, User
from .routeros import RouterOSClient, RouterConnectionError
from .schemas import ClientConfigRequest, PeerCreate
from .security import decrypt_secret, encrypt_secret
from io import BytesIO
import qrcode
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

def _overlaps(address: str, candidate: str) -> bool:
    try:
        proposed = ipaddress.ip_interface(address).network
        existing = ipaddress.ip_interface(candidate).network
        return proposed.version == existing.version and proposed.overlaps(existing)
    except ValueError:
        return False

def _router_peer_path(peer_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9*_.-]{1,120}", peer_id):
        raise RouterConnectionError("RouterOS returned an invalid peer identifier")
    return f"/interface/wireguard/peers/{peer_id}"

def _router(db: Session, router_id: int) -> Router:
    item = db.get(Router, router_id)
    if not item:
        raise HTTPException(404, "Router not found")
    return item

@router.post("/preview")
async def preview_peer(router_id: int, body: PeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    item = _router(db, router_id)
    address = validate_address(body.allowed_address)
    networks = normalize_networks(body.access_networks)
    if any(ipaddress.ip_network(n).version != ipaddress.ip_interface(address).version for n in networks):
        raise HTTPException(422, "Destination network IP family must match the peer address")
    for peer in db.query(Peer).filter(Peer.router_id == router_id, Peer.status != "revoked").all():
        if _overlaps(address, peer.allowed_address):
            raise HTTPException(409, "Address overlaps an allocation in the local inventory")
    client = RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)
    try:
        interfaces = await client.get("/interface/wireguard")
        remote_peers = await client.get("/interface/wireguard/peers")
    except RouterConnectionError:
        raise HTTPException(502, "Unable to verify router-side interface and address conflicts")
    interfaces = interfaces if isinstance(interfaces, list) else [interfaces]
    remote_peers = remote_peers if isinstance(remote_peers, list) else [remote_peers]
    if not any(x.get("name") == body.interface_name for x in interfaces):
        raise HTTPException(422, "The selected WireGuard interface does not exist on this router")
    for peer in remote_peers:
        for candidate in str(peer.get("allowed-address", "")).split(","):
            if candidate.strip() and _overlaps(address, candidate.strip()):
                raise HTTPException(409, "Address overlaps an existing router-side peer")
    return {"dry_run": True, "router_id": router_id, "interface_name": body.interface_name, "name": body.name, "allowed_address": address, "router_conflicts_checked": True, "will_create_router_peer": True, "will_store_private_key_encrypted": True, "requires_explicit_confirmation": True, "mutations_enabled": get_settings().enable_peer_mutations}

@router.post("", status_code=201)
async def create_peer(router_id: int, body: PeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    if body.dry_run or not body.confirm:
        raise HTTPException(409, "Mutation requires dry_run=false and confirm=true after reviewing /preview")
    if not get_settings().enable_peer_mutations:
        raise HTTPException(503, "Live peer mutations are disabled by deployment policy")
    item = _router(db, router_id)
    address = validate_address(body.allowed_address)
    networks = normalize_networks(body.access_networks)
    if any(ipaddress.ip_network(n).version != ipaddress.ip_interface(address).version for n in networks):
        raise HTTPException(422, "Destination network IP family must match the peer address; dual-stack peers need separate addresses")
    await preview_peer(router_id, body, db, user)
    private_key, public_key = generate_keypair()
    client = RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)
    remote_id = None
    peer = None
    try:
        created = await client.post("/interface/wireguard/peers", {
            "interface": body.interface_name, "public-key": public_key,
            "allowed-address": address, "comment": body.name, "disabled": "true",
        })
        remote_id = created.get(".id")
        if not remote_id:
            raise HTTPException(502, "RouterOS may have created a disabled peer but returned no identifier; inspect the router")
        peer = Peer(router_id=router_id, router_peer_id=str(remote_id), name=body.name,
            public_key=public_key, private_key_ciphertext=encrypt_secret(private_key),
            allowed_address=address, endpoint=body.endpoint,
            access_networks_json=__import__("json").dumps(networks), status="active")
        db.add(peer)
        db.flush()
        record_event(db, user.username, "peer.create", "peer", str(peer.id),
            details={"router_id": router_id, "interface": body.interface_name, "allowed_address": address,
                     "access_networks": networks, "router_peer_id": str(remote_id), "initially_disabled": True})
        db.commit()
    except Exception as exc:
        db.rollback()
        if remote_id:
            try:
                await client.delete(_router_peer_path(str(remote_id)))
            except Exception:
                record_event(db, user.username, "peer.create.rollback_failed", "router", str(router_id),
                    outcome="critical", details={"router_peer_id": str(remote_id)})
                db.commit()
                raise HTTPException(500, "Peer creation failed and remote cleanup could not be confirmed; inspect RouterOS") from exc
        if isinstance(exc, HTTPException):
            raise
        if isinstance(exc, RouterConnectionError):
            raise HTTPException(502, "RouterOS peer creation did not complete cleanly; inspect the router before retrying") from exc
        raise HTTPException(500, "Peer creation failed and remote cleanup was attempted") from exc

    # ACL is installed while the peer remains disabled; only activate after successful enforcement.
    try:
        await update_peer_access_control(router_id, peer.id, {"access_networks": networks}, db, user)
        await client.patch(_router_peer_path(str(remote_id)), {"disabled": "false"})
    except Exception as exc:
        peer.status = "pending"
        record_event(db, user.username, "peer.create.acl_or_enable_failed", "peer", str(peer.id),
            outcome="failed", details={"router_id": router_id, "peer_remains_disabled": True})
        db.commit()
        if isinstance(exc, HTTPException):
            raise HTTPException(502, "Peer remains disabled because ACL application or activation was not confirmed; inspect RouterOS before retrying") from exc
        raise HTTPException(502, "Peer remains disabled because ACL application or activation was not confirmed") from exc
    peer.status = "active"
    db.commit()
    return {"id": peer.id, "router_id": router_id, "name": peer.name, "public_key": peer.public_key,
        "allowed_address": peer.allowed_address, "access_networks": networks, "status": peer.status,
        "created_at": peer.created_at.isoformat(), "private_key_returned": False}

@router.put("/{peer_id}/access-control")
async def update_peer_access_control(router_id: int, peer_id: int, body: dict, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    """Apply a per-peer destination allowlist on RouterOS. Empty list means deny all forwarded destinations."""
    import json
    try:
        networks = normalize_networks(body.get("access_networks", []))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    item = _router(db, router_id)
    peer = db.query(Peer).filter(Peer.id == peer_id, Peer.router_id == router_id, Peer.status == "active").first()
    if not peer or not peer.router_peer_id:
        raise HTTPException(404, "Active synchronized peer not found")
    client = RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)
    marker = f"wgm-acl-peer-{peer.id}-"
    try:
        existing = await client.get("/ip/firewall/filter")
        existing = existing if isinstance(existing, list) else [existing]
        plan = routeros_rule_plan(peer.id, peer.allowed_address, networks)
        created_ids = []
        for rule in reversed(plan):
            result = await client.post("/ip/firewall/filter", {**rule, "place-before": "0"})
            if result.get(".id"):
                created_ids.append(str(result[".id"]))
        for rule in existing:
            if str(rule.get("comment", "")).startswith(marker) and str(rule.get(".id")) not in created_ids:
                await client.delete("/ip/firewall/filter/" + str(rule[".id"]))
    except RouterConnectionError as exc:
        record_event(db, user.username, "peer.access_control.apply", "peer", str(peer.id), outcome="failed", details={"router_id": router_id, "network_count": len(networks)})
        db.commit()
        raise HTTPException(502, "RouterOS ACL application was not confirmed; inspect firewall rules before retrying") from exc
    peer.access_networks_json = json.dumps(networks)
    record_event(db, user.username, "peer.access_control.apply", "peer", str(peer.id), details={"router_id": router_id, "network_count": len(networks), "default_deny": True})
    db.commit()
    return {"peer_id": peer.id, "access_networks": networks, "default_deny": True, "enforcement": "routeros-firewall"}

@router.delete("/{peer_id}", status_code=200)
async def revoke_peer(router_id: int, peer_id: int, confirm: bool = False, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    if not confirm:
        raise HTTPException(409, "Revocation requires explicit confirm=true")
    if not get_settings().enable_peer_mutations:
        raise HTTPException(503, "Live peer mutations are disabled by deployment policy")
    item = _router(db, router_id)
    peer = db.query(Peer).filter(Peer.id == peer_id, Peer.router_id == router_id, Peer.status != "revoked").first()
    if not peer:
        raise HTTPException(404, "Active peer not found")
    if not peer.router_peer_id:
        raise HTTPException(409, "Peer has no synchronized RouterOS identifier; refusing unsafe revoke")
    client = RouterOSClient(item.host, item.port, item.username, item.credential_ciphertext, item.tls_verify)
    remote_path = _router_peer_path(peer.router_peer_id)
    try:
        # Disable first rather than delete, allowing a compensating rollback if DB commit fails.
        await client.patch(remote_path, {"disabled": "true"})
    except RouterConnectionError as exc:
        record_event(db, user.username, "peer.revoke", "peer", str(peer.id), outcome="failed", details={"reason": "router_disable_failed"})
        db.commit()
        raise HTTPException(502, "RouterOS did not confirm peer disable; local state was not changed") from exc
    peer.status = "revoked"
    peer.private_key_ciphertext = None
    record_event(db, user.username, "peer.revoke", "peer", str(peer.id), details={"router_id": router_id, "router_peer_id": peer.router_peer_id, "router_action": "disable"})
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        try:
            await client.patch(remote_path, {"disabled": "false"})
        except Exception as rollback_exc:
            record_event(db, user.username, "peer.revoke.rollback_failed", "peer", str(peer_id), outcome="critical", details={"router_id": router_id, "router_peer_id": peer.router_peer_id})
            db.commit()
            raise HTTPException(500, "Database commit failed and RouterOS re-enable rollback failed; reconcile manually") from rollback_exc
        raise HTTPException(500, "Database commit failed; router peer was re-enabled") from exc
    return {"id": peer.id, "status": peer.status, "revoked_at": datetime.now(timezone.utc).isoformat()}


def _client_config(peer: Peer, body: ClientConfigRequest, db: Session, user: User) -> str:
    if peer.status != "active" or not peer.private_key_ciphertext:
        raise HTTPException(409, "Client configuration is unavailable for a revoked or unsynchronized peer")
    try:
        private_key = decrypt_secret(peer.private_key_ciphertext)
    except RuntimeError as exc:
        raise HTTPException(500, "Peer key cannot be decrypted; verify the configured encryption key and backups") from exc
    config = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {peer.allowed_address}\n"
        f"DNS = {body.dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {body.server_public_key}\n"
        f"AllowedIPs = {body.allowed_ips}\n"
        f"Endpoint = {body.endpoint}\n"
        f"PersistentKeepalive = {body.persistent_keepalive}\n"
    )
    # Audit metadata only; never include key material or the generated config in logs.
    record_event(db, user.username, "peer.config.issue", "peer", str(peer.id), details={"router_id": peer.router_id, "format": "wireguard-conf"})
    db.commit()
    return config

def _config_peer(router_id: int, peer_id: int, db: Session) -> Peer:
    peer = db.query(Peer).filter(Peer.id == peer_id, Peer.router_id == router_id).first()
    if not peer:
        raise HTTPException(404, "Peer not found")
    return peer

@router.post("/{peer_id}/config")
def download_client_config(router_id: int, peer_id: int, body: ClientConfigRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    peer = _config_peer(router_id, peer_id, db)
    config = _client_config(peer, body, db, user)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", peer.name)[:80] or f"peer-{peer.id}"
    return Response(content=config, media_type="text/plain; charset=utf-8", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="{safe_name}.conf"',
    })

@router.post("/{peer_id}/qr")
def download_client_qr(router_id: int, peer_id: int, body: ClientConfigRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    peer = _config_peer(router_id, peer_id, db)
    config = _client_config(peer, body, db, user)
    image = qrcode.make(config)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return Response(content=buffer.getvalue(), media_type="image/png", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'attachment; filename="peer-{peer.id}.png"',
    })
