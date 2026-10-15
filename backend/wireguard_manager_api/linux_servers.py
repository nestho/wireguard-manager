"""Linux WireGuard server onboarding and operations over pinned-host-key SSH."""
import asyncio
import ipaddress
import re
import shlex
from datetime import datetime, timezone
import asyncssh
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .audit import record_event
from .config import get_settings
from .db import get_db
from .dependencies import current_user, require_roles
from .models import LinuxServer, User
from .schemas import LinuxInstallRequest, LinuxServerCreate
from .security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/linux-servers", tags=["linux-servers"])

class PinnedHostKeyClient(asyncssh.SSHClient):
    def __init__(self, expected: str):
        self.expected = expected
    def validate_host_public_key(self, host, addr, port, key):
        return key.get_fingerprint("sha256") == self.expected

def validate_linux_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host.strip())
    except ValueError as exc:
        raise ValueError("Linux server host must be an IP literal; DNS names are disabled to prevent DNS rebinding") from exc
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ValueError("Loopback, link-local, multicast, reserved, and unspecified addresses are not allowed")
    if not address.is_private and not get_settings().allow_public_linux_hosts:
        raise ValueError("Public Linux hosts are disabled by default; enable WGM_ALLOW_PUBLIC_LINUX_HOSTS only after reviewing SSH egress controls")
    return str(address)

async def _connect(server: LinuxServer):
    try:
        private_key = asyncssh.import_private_key(decrypt_secret(server.private_key_ciphertext))
        conn = await asyncssh.connect(
            server.host, port=server.port, username=server.username,
            client_keys=[private_key], known_hosts=[],
            client_factory=lambda: PinnedHostKeyClient(server.host_key_fingerprint),
            connect_timeout=5, login_timeout=8, keepalive_interval=15,
            keepalive_count_max=2,
        )
        return conn
    except Exception as exc:
        raise HTTPException(502, "SSH connection or pinned host-key verification failed; verify reachability, credentials, and fingerprint") from exc

async def _run(conn, command: str, timeout: int = 20):
    result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
    stdout = result.stdout if isinstance(result.stdout, str) else result.stdout.decode(errors="replace")
    stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode(errors="replace")
    if result.exit_status != 0:
        raise HTTPException(502, "Remote command failed (exit " + str(result.exit_status) + "): " + (stderr[-400:] or "no error details"))
    return stdout

def _server_view(server: LinuxServer):
    return {"id": server.id, "name": server.name, "host": server.host, "port": server.port, "username": server.username,
        "distro_id": server.distro_id, "distro_version": server.distro_version, "package_manager": server.package_manager,
        "wireguard_installed": server.wireguard_installed, "last_status": server.last_status,
        "last_check_at": server.last_check_at.isoformat() if server.last_check_at else None, "created_at": server.created_at.isoformat()}

def _server(db: Session, server_id: int) -> LinuxServer:
    server = db.get(LinuxServer, server_id)
    if not server:
        raise HTTPException(404, "Linux server not found")
    return server

@router.get("")
def list_linux_servers(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [_server_view(x) for x in db.query(LinuxServer).order_by(LinuxServer.id.desc()).all()]

@router.post("", status_code=201)
async def register_linux_server(body: LinuxServerCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    try:
        host = validate_linux_host(body.host)
        asyncssh.import_private_key(body.ssh_private_key)
    except (ValueError, asyncssh.KeyImportError) as exc:
        raise HTTPException(422, "Invalid host or SSH private key: " + str(exc))
    server = LinuxServer(name=body.name, host=host, port=body.port, username=body.username,
        private_key_ciphertext=encrypt_secret(body.ssh_private_key), host_key_fingerprint=body.host_key_fingerprint,
        last_status="unverified")
    db.add(server)
    db.flush()
    record_event(db, user.username, "linux_server.register", "linux_server", str(server.id), details={"host": host, "port": body.port, "host_key_pinned": True})
    db.commit()
    return _server_view(server)

@router.post("/{server_id}/inspect")
async def inspect_linux_server(server_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    server = _server(db, server_id)
    conn = await _connect(server)
    try:
        output = await _run(conn, "cat /etc/os-release; printf '\\n--KERNEL--\\n'; uname -srmo; printf '\\n--PRIVILEGE--\\n'; id -u; printf '\\n--TOOLS--\\n'; command -v wg || true; command -v wg-quick || true; command -v systemctl || true; command -v apt-get || true; command -v dnf || true; command -v yum || true; command -v zypper || true; command -v apk || true")
    finally:
        conn.close()
        await conn.wait_closed()
    sections = output.split("--KERNEL--", 1)
    os_text = sections[0]
    values = {}
    for line in os_text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v.strip().strip('"')
    distro = values.get("ID", "unknown").lower()
    version = values.get("VERSION_ID", "unknown")
    tools = output.split("--TOOLS--", 1)[-1]
    pm = next((name for name in ("apt-get", "dnf", "yum", "zypper", "apk") if re.search(r"(^|/)"+re.escape(name)+r"\s*$", tools, re.M)), None)
    installed = bool(re.search(r"(^|/)wg\s*$", tools, re.M) and re.search(r"(^|/)wg-quick\s*$", tools, re.M))
    supported = distro in {"ubuntu", "debian", "linuxmint", "pop"} and pm == "apt-get" or distro in {"fedora", "rhel", "centos", "rocky", "almalinux", "ol"} and pm in {"dnf", "yum"} or distro in {"opensuse-leap", "opensuse-tumbleweed", "sles"} and pm == "zypper" or distro in {"alpine"} and pm == "apk"
    server.distro_id, server.distro_version, server.package_manager = distro, version, pm
    server.wireguard_installed = installed
    server.last_status = "healthy" if supported else "unsupported"
    server.last_check_at = datetime.now(timezone.utc)
    record_event(db, user.username, "linux_server.inspect", "linux_server", str(server.id), outcome="success" if supported else "warning", details={"distro": distro, "version": version, "package_manager": pm, "wireguard_installed": installed})
    db.commit()
    return {"server": _server_view(server), "kernel": sections[1].split("--PRIVILEGE--",1)[0].strip() if len(sections)>1 else "unknown",
        "root_or_sudo_check": "inspection ran as configured SSH user; privileged operations require sudo -n",
        "supported": supported, "wireguard_installed": installed,
        "install_plan": _install_plan(distro, pm) if supported and not installed else [],
        "inspected_at": server.last_check_at.isoformat()}

def _install_plan(distro: str | None, pm: str | None):
    if pm == "apt-get" and distro in {"ubuntu", "debian", "linuxmint", "pop"}:
        return [{"step": "refresh package index", "command": "sudo -n apt-get update"}, {"step": "install WireGuard tools", "command": "sudo -n apt-get install -y wireguard wireguard-tools"}]
    if pm in {"dnf", "yum"} and distro in {"fedora", "rhel", "centos", "rocky", "almalinux", "ol"}:
        return [{"step": "install WireGuard tools", "command": "sudo -n "+pm+" install -y wireguard-tools"}]
    if pm == "zypper" and distro in {"opensuse-leap", "opensuse-tumbleweed", "sles"}:
        return [{"step": "install WireGuard tools", "command": "sudo -n zypper --non-interactive install wireguard-tools"}]
    if pm == "apk" and distro == "alpine":
        return [{"step": "install WireGuard tools", "command": "sudo -n apk add wireguard-tools"}]
    return []

@router.post("/{server_id}/install/preview")
def preview_install(server_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    server = _server(db, server_id)
    if not server.distro_id or not server.package_manager:
        raise HTTPException(409, "Inspect the server before requesting an install plan")
    if server.wireguard_installed:
        return {"ready": True, "already_installed": True, "plan": [], "requires_confirmation": False}
    plan = _install_plan(server.distro_id, server.package_manager)
    if not plan:
        raise HTTPException(422, "This distribution/package manager combination is not supported for automatic installation")
    return {"ready": True, "already_installed": False, "plan": plan, "requires_confirmation": True,
        "warning": "Package installation changes the host and requires non-interactive sudo privileges. Review the plan and change window before confirming."}

@router.post("/{server_id}/install")
async def install_wireguard(server_id: int, body: LinuxInstallRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    if not get_settings().enable_linux_mutations:
        raise HTTPException(503, "Linux installation and peer mutations are disabled by deployment policy")
    if not body.confirm:
        raise HTTPException(409, "Explicit confirm=true is required after reviewing the installation plan")
    server = _server(db, server_id)
    if not server.distro_id or not server.package_manager:
        raise HTTPException(409, "Inspect the server before installation")
    if server.wireguard_installed:
        return {"status": "already_installed", "server_id": server.id}
    plan = _install_plan(server.distro_id, server.package_manager)
    if not plan:
        raise HTTPException(422, "Unsupported Linux distribution")
    conn = await _connect(server)
    results = []
    try:
        for step in plan:
            results.append({"step": step["step"], "output": (await _run(conn, step["command"], timeout=180))[-2000:]})
        verify = await _run(conn, "command -v wg && command -v wg-quick")
    finally:
        conn.close()
        await conn.wait_closed()
    server.wireguard_installed = True
    server.last_status = "healthy"
    server.last_check_at = datetime.now(timezone.utc)
    record_event(db, user.username, "linux_server.wireguard_install", "linux_server", str(server.id), details={"distro": server.distro_id, "version": server.distro_version, "steps": [x["step"] for x in results]})
    db.commit()
    return {"status": "installed", "server": _server_view(server), "steps": results, "verification": verify.strip()}
