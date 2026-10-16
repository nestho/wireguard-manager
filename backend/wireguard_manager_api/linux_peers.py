"""Linux WireGuard peer lifecycle with explicit confirmation and rollback attempts."""
import base64
import ipaddress
import re
import shlex
from datetime import datetime, timezone
from io import BytesIO
import qrcode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from .access_control import normalize_networks, nft_rules
from .audit import record_event
from .config import get_settings
from .db import get_db
from .dependencies import current_user, require_roles
from .linux_servers import _connect, _run, _server
from .models import LinuxPeer, User
from .schemas import AccessControlRequest, ClientConfigRequest, LinuxPeerCreate
from .security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/linux-servers/{server_id}/peers", tags=["linux-peers"])

def _address(value: str) -> str:
    try:
        addr = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise HTTPException(422, "Use a valid peer address such as 10.20.0.2/32") from exc
    if addr.ip.is_loopback or addr.ip.is_link_local or addr.ip.is_multicast or addr.ip.is_unspecified:
        raise HTTPException(422, "Loopback, link-local, multicast and unspecified peer addresses are not allowed")
    if addr.version == 4 and addr.network.prefixlen < 24 or addr.version == 6 and addr.network.prefixlen < 64:
        raise HTTPException(422, "Peer prefix is too broad; use IPv4 /24-/32 or IPv6 /64-/128")
    return str(addr)

def _access_networks(values):
    try:
        return normalize_networks(values)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc

def _keypair():
    private = X25519PrivateKey.generate()
    return (base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
            base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())

def _iface(value: str):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value):
        raise HTTPException(422, "Invalid WireGuard interface name")
    return value

def _peer_view(peer: LinuxPeer):
    import json
    return {"id": peer.id, "server_id": peer.server_id, "interface_name": peer.interface_name, "name": peer.name,
            "public_key": peer.public_key, "allowed_address": peer.allowed_address, "access_networks": json.loads(peer.access_networks_json or "[]"), "status": peer.status,
            "created_at": peer.created_at.isoformat()}

@router.get("")
def list_peers(server_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _server(db, server_id)
    return [_peer_view(p) for p in db.query(LinuxPeer).filter_by(server_id=server_id).order_by(LinuxPeer.id.desc()).all()]

@router.get("/remote")
async def discover_remote_peers(server_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    server = _server(db, server_id)
    conn = await _connect(server)
    try:
        interfaces = (await _run(conn, "sudo -n wg show interfaces")).split()
        result = []
        for iface in interfaces:
            _iface(iface)
            raw = await _run(conn, "sudo -n wg show " + shlex.quote(iface) + " dump")
            lines = raw.splitlines()
            for line in lines[1:]:
                cols = line.split("\t")
                if len(cols) >= 8:
                    result.append({"interface_name": iface, "public_key": cols[0], "endpoint": cols[2],
                        "allowed_ips": cols[3], "latest_handshake_epoch": int(cols[4] or 0),
                        "rx_bytes": int(cols[5] or 0), "tx_bytes": int(cols[6] or 0), "persistent_keepalive": cols[7]})
        return {"server_id": server_id, "interfaces": interfaces, "peers": result,
                "retrieved_at": datetime.now(timezone.utc).isoformat(), "historical": False}
    finally:
        conn.close()
        await conn.wait_closed()

@router.post("/preview")
async def preview_peer(server_id: int, body: LinuxPeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    server = _server(db, server_id)
    address = _address(body.allowed_address)
    networks = _access_networks(body.access_networks)
    if any(ipaddress.ip_network(n).version != ipaddress.ip_interface(address).version for n in networks):
        raise HTTPException(422, "Destination network IP family must match the peer address")
    _iface(body.interface_name)
    for peer in db.query(LinuxPeer).filter_by(server_id=server_id, status="active").all():
        if ipaddress.ip_interface(peer.allowed_address).network.overlaps(ipaddress.ip_interface(address).network):
            raise HTTPException(409, "Address overlaps a local Linux peer allocation")
    conn = await _connect(server)
    try:
        interfaces = (await _run(conn, "sudo -n wg show interfaces")).split()
        if body.interface_name not in interfaces:
            raise HTTPException(422, "The selected WireGuard interface is not active on the server")
        raw = await _run(conn, "sudo -n wg show " + shlex.quote(body.interface_name) + " allowed-ips")
        for line in raw.splitlines():
            cols = line.split(None, 1)
            if len(cols) == 2 and cols[1] != "(none)":
                for existing in cols[1].split(","):
                    try:
                        network = ipaddress.ip_network(existing.strip(), strict=False)
                        if network.version == ipaddress.ip_interface(address).version and network.overlaps(ipaddress.ip_interface(address).network):
                            raise HTTPException(409, "Address overlaps an existing peer on the Linux server")
                    except ValueError:
                        continue
        # Require wg-quick-managed persistent configuration before any mutation.
        await _run(conn, "sudo -n test -f " + shlex.quote("/etc/wireguard/" + body.interface_name + ".conf"))
    finally:
        conn.close()
        await conn.wait_closed()
    return {"dry_run": True, "server_id": server_id, "interface_name": body.interface_name, "name": body.name,
        "allowed_address": address, "router_conflicts_checked": True, "persistent_config_found": True,
        "requires_explicit_confirmation": True, "mutations_enabled": get_settings().enable_linux_mutations}

@router.post("", status_code=201)
async def create_peer(server_id: int, body: LinuxPeerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    if body.dry_run or not body.confirm:
        raise HTTPException(409, "Mutation requires dry_run=false and confirm=true after reviewing /preview")
    if not get_settings().enable_linux_mutations:
        raise HTTPException(503, "Linux peer mutations are disabled by deployment policy")
    await preview_peer(server_id, body, db, user)
    server = _server(db, server_id)
    private_key, public_key = _keypair()
    address = _address(body.allowed_address)
    iface = _iface(body.interface_name)
    conn = await _connect(server)
    try:
        await _run(conn, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(public_key) + " allowed-ips " + shlex.quote(address))
        try:
            await _run(conn, "sudo -n wg-quick save " + shlex.quote(iface), timeout=30)
        except HTTPException as save_error:
            try:
                await _run(conn, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(public_key) + " remove")
            except HTTPException as rollback_error:
                record_event(db, user.username, "linux_peer.create.rollback_failed", "linux_server", str(server_id), outcome="critical", details={"interface": iface, "public_key": public_key})
                db.commit()
                raise HTTPException(500, "Persistence failed and peer removal rollback failed; reconcile the server manually") from rollback_error
            raise save_error
    finally:
        conn.close()
        await conn.wait_closed()
    peer = LinuxPeer(server_id=server_id, interface_name=iface, name=body.name, public_key=public_key,
        private_key_ciphertext=encrypt_secret(private_key), allowed_address=address, access_networks_json=__import__("json").dumps(_access_networks(body.access_networks)), status="active")
    db.add(peer)
    try:
        db.flush()
        record_event(db, user.username, "linux_peer.create", "linux_peer", str(peer.id), details={"server_id": server_id, "interface": iface, "allowed_address": address})
        db.commit()
    except Exception as exc:
        db.rollback()
        rollback = await _connect(server)
        try:
            await _run(rollback, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(public_key) + " remove")
            await _run(rollback, "sudo -n wg-quick save " + shlex.quote(iface), timeout=30)
        except Exception as rollback_exc:
            raise HTTPException(500, "Database persistence failed and remote rollback could not be confirmed; reconcile manually") from rollback_exc
        finally:
            rollback.close()
            await rollback.wait_closed()
        raise HTTPException(500, "Database persistence failed; remote peer rollback was attempted") from exc
    try:
        await update_peer_access_control(server_id, peer.id, AccessControlRequest(access_networks=body.access_networks), db, user)
    except Exception as acl_exc:
        # Best-effort fail-closed compensation: remove the peer if its firewall policy cannot be confirmed.
        cleanup = await _connect(server)
        try:
            await _run(cleanup, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(public_key) + " remove")
            await _run(cleanup, "sudo -n wg-quick save " + shlex.quote(iface), timeout=30)
            peer.status = "revoked"
            peer.private_key_ciphertext = None
            record_event(db, user.username, "linux_peer.create.acl_rollback", "linux_peer", str(peer.id), outcome="failed", details={"server_id": server_id})
            db.commit()
        except Exception as cleanup_exc:
            record_event(db, user.username, "linux_peer.create.acl_rollback_failed", "linux_peer", str(peer.id), outcome="critical", details={"server_id": server_id})
            db.commit()
            raise HTTPException(500, "ACL could not be confirmed and peer rollback failed; manually remove or isolate the peer") from cleanup_exc
        finally:
            cleanup.close()
            await cleanup.wait_closed()
        raise HTTPException(502, "ACL could not be confirmed; the new peer was revoked") from acl_exc
    return {**_peer_view(peer), "access_networks": _access_networks(body.access_networks), "private_key_returned": False, "client_config_available": True}

@router.get("/{peer_id}/access-control")
def get_peer_access_control(server_id: int, peer_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    peer = db.query(LinuxPeer).filter_by(id=peer_id, server_id=server_id).first()
    if not peer:
        raise HTTPException(404, "Linux peer not found")
    import json
    networks = json.loads(peer.access_networks_json or "[]")
    return {"peer_id": peer.id, "access_networks": networks, "default_deny": not bool(networks), "enforcement": "linux-nftables" if peer.status == "active" else "not-active"}

@router.put("/{peer_id}/access-control")
async def update_peer_access_control(server_id: int, peer_id: int, body: AccessControlRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    """Apply a per-peer destination allowlist using nftables; empty list means deny all forwarded destinations."""
    import json
    try:
        networks = _access_networks(body.access_networks)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    server = _server(db, server_id)
    peer = db.query(LinuxPeer).filter_by(id=peer_id, server_id=server_id, status="active").first()
    if not peer:
        raise HTTPException(404, "Active Linux peer not found")
    source = ipaddress.ip_interface(peer.allowed_address).ip
    if any(ipaddress.ip_network(network).version != source.version for network in networks):
        raise HTTPException(422, "Destination network IP family must match this peer address; dual-stack peers need separate IPv4 and IPv6 addresses")
    table = f"wgm_acl_{peer.id}"
    full_rules = nft_rules(peer.id, peer.allowed_address, networks)
    conn = await _connect(server)
    temp_path = f"/tmp/{table}.nft"
    target_path = f"/etc/nftables.d/{table}.nft"
    try:
        # Refuse to claim persistence unless nftables.conf loads the managed drop-in directory.
        await _run(conn, "sudo -n test -r /etc/nftables.conf && sudo -n grep -Eq 'include[[:space:]]+.*nftables.d/.*\\.nft|include[[:space:]]+.*nftables.d/\\*' /etc/nftables.conf")
        await _run(conn, "sudo -n test -d /etc/nftables.d")
        sftp = await conn.start_sftp_client()
        try:
            async with sftp.open(temp_path, "w") as handle:
                await handle.write(full_rules)
        finally:
            sftp.exit()
        # The transaction script flushes the existing managed chain atomically when it already exists.
        exists = True
        try:
            await _run(conn, "sudo -n nft list table inet " + table)
        except HTTPException:
            exists = False
        apply_rules = full_rules
        if exists:
            rule_lines = [line for line in full_rules.splitlines() if line.strip().endswith(" accept") or line.strip().endswith(" drop")]
            apply_rules = f"flush chain inet {table} forward_guard\\n" + "\\n".join(rule_lines) + "\\n"
            sftp2 = await conn.start_sftp_client()
            try:
                async with sftp2.open(temp_path, "w") as handle:
                    await handle.write(apply_rules)
            finally:
                sftp2.exit()
        await _run(conn, "sudo -n nft -c -f " + shlex.quote(temp_path))
        # Save the full declarative file separately so boot-time include replays the same ACL.
        sftp3 = await conn.start_sftp_client()
        try:
            async with sftp3.open(temp_path, "w") as handle:
                await handle.write(full_rules)
        finally:
            sftp3.exit()
        await _run(conn, "sudo -n install -o root -g root -m 0644 " + shlex.quote(temp_path) + " " + shlex.quote(target_path))
        # Apply transaction from the full file on first install, or a flush-chain transaction on update.
        if exists:
            update_path = f"/tmp/{table}-update.nft"
            sftp4 = await conn.start_sftp_client()
            try:
                async with sftp4.open(update_path, "w") as handle:
                    await handle.write(apply_rules)
            finally:
                sftp4.exit()
            await _run(conn, "sudo -n nft -f " + shlex.quote(update_path))
        else:
            await _run(conn, "sudo -n nft -f " + shlex.quote(target_path))
    except HTTPException as exc:
        record_event(db, user.username, "linux_peer.access_control.apply", "linux_peer", str(peer.id), outcome="failed", details={"server_id": server_id, "network_count": len(networks)})
        db.commit()
        raise HTTPException(502, "Linux ACL was not confirmed; inspect nftables state and the persistent drop-in before retrying") from exc
    finally:
        conn.close()
        await conn.wait_closed()
    peer.access_networks_json = json.dumps(networks)
    record_event(db, user.username, "linux_peer.access_control.apply", "linux_peer", str(peer.id), details={"server_id": server_id, "network_count": len(networks), "default_deny": True})
    db.commit()
    return {"peer_id": peer.id, "access_networks": networks, "default_deny": True, "enforcement": "linux-nftables"}

@router.delete("/{peer_id}")
async def revoke_peer(server_id: int, peer_id: int, confirm: bool = False, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    if not confirm:
        raise HTTPException(409, "Revocation requires explicit confirm=true")
    if not get_settings().enable_linux_mutations:
        raise HTTPException(503, "Linux peer mutations are disabled by deployment policy")
    server = _server(db, server_id)
    peer = db.query(LinuxPeer).filter_by(id=peer_id, server_id=server_id, status="active").first()
    if not peer:
        raise HTTPException(404, "Active Linux peer not found")
    iface, key = _iface(peer.interface_name), peer.public_key
    conn = await _connect(server)
    try:
        await _run(conn, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(key) + " remove")
        try:
            await _run(conn, "sudo -n wg-quick save " + shlex.quote(iface), timeout=30)
        except HTTPException as save_error:
            try:
                await _run(conn, "sudo -n wg set " + shlex.quote(iface) + " peer " + shlex.quote(key) + " allowed-ips " + shlex.quote(peer.allowed_address))
                await _run(conn, "sudo -n wg-quick save " + shlex.quote(iface), timeout=30)
            except HTTPException as rollback_error:
                raise HTTPException(500, "Persistent save failed and live peer rollback failed; reconcile manually") from rollback_error
            raise save_error
    finally:
        conn.close()
        await conn.wait_closed()
    peer.status = "revoked"
    peer.private_key_ciphertext = None
    record_event(db, user.username, "linux_peer.revoke", "linux_peer", str(peer.id), details={"server_id": server_id, "interface": iface})
    db.commit()
    return {"id": peer.id, "status": peer.status, "revoked_at": datetime.now(timezone.utc).isoformat()}

@router.post("/{peer_id}/config")
def download_config(server_id: int, peer_id: int, body: ClientConfigRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    peer = db.query(LinuxPeer).filter_by(id=peer_id, server_id=server_id).first()
    if not peer:
        raise HTTPException(404, "Peer not found")
    if peer.status != "active" or not peer.private_key_ciphertext:
        raise HTTPException(409, "Client configuration is unavailable for a revoked peer")
    try:
        private_key = decrypt_secret(peer.private_key_ciphertext)
    except RuntimeError as exc:
        raise HTTPException(500, "Peer key cannot be decrypted; verify the encryption key and backups") from exc
    access_networks = __import__("json").loads(peer.access_networks_json or "[]")
    client_allowed_ips = ", ".join(access_networks) if access_networks else body.allowed_ips
    config = "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + peer.allowed_address + "\nDNS = " + body.dns + "\n\n[Peer]\nPublicKey = " + body.server_public_key + "\nAllowedIPs = " + client_allowed_ips + "\nEndpoint = " + body.endpoint + "\nPersistentKeepalive = " + str(body.persistent_keepalive) + "\n"
    record_event(db, user.username, "linux_peer.config.issue", "linux_peer", str(peer.id), details={"server_id": server_id, "format": "wireguard-conf"})
    db.commit()
    return Response(content=config, media_type="text/plain; charset=utf-8", headers={"Cache-Control": "no-store, no-cache, must-revalidate, private", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Content-Disposition": 'attachment; filename="linux-peer-'+str(peer.id)+'.conf"'})

@router.post("/{peer_id}/qr")
def download_qr(server_id: int, peer_id: int, body: ClientConfigRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    config_response = download_config(server_id, peer_id, body, db, user)
    image = qrcode.make(config_response.body.decode())
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return Response(content=buffer.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store, no-cache, must-revalidate, private", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Content-Disposition": 'attachment; filename="linux-peer-'+str(peer_id)+'.png"'})
