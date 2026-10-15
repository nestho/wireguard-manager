"""Narrow RouterOS REST client. Uses TLS verification and exposes read operations only."""
import ipaddress
import socket
from urllib.parse import urlsplit
import httpx
from .config import get_settings
from .security import decrypt_secret

class RouterConnectionError(RuntimeError):
    pass

def validate_router_host(host: str) -> str:
    host = host.strip().rstrip(".")
    if not host or any(c in host for c in "/\\@?#"):
        raise ValueError("Host must be a hostname or IP address, without URL/path components")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Loopback, link-local, multicast, and unspecified addresses are not allowed")
        if not ip.is_private and not get_settings().allow_public_router_hosts:
            raise ValueError("Public router addresses are disabled by default; enable explicitly after reviewing network egress controls")
        return str(ip)
    except ValueError as exc:
        if "not allowed" in str(exc) or "disabled" in str(exc):
            raise
    labels = host.split(".")
    if len(host) > 253 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError("Invalid hostname")
    return host

class RouterOSClient:
    def __init__(self, host: str, port: int, username: str, encrypted_password: str, verify_tls: bool = True):
        self.host = validate_router_host(host)
        self.base_url = f"https://{self.host}:{port}/rest"
        self.username = username
        self.password = decrypt_secret(encrypted_password)
        self.verify_tls = verify_tls

    async def get(self, path: str) -> list[dict] | dict:
        if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("Invalid RouterOS REST path")
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False) as client:
                response = await client.get(f"{self.base_url}{path}", auth=(self.username, self.password))
                if response.status_code in (301, 302, 307, 308):
                    raise RouterConnectionError("Router returned a redirect; redirects are blocked")
                if response.status_code == 401:
                    raise RouterConnectionError("Router authentication failed")
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, (list, dict)):
                    raise RouterConnectionError("Unexpected RouterOS response format")
                return data
        except (httpx.HTTPError, ValueError) as exc:
            if isinstance(exc, RouterConnectionError):
                raise
            raise RouterConnectionError("Router request failed; check reachability, HTTPS, certificate, and read-only account") from exc
