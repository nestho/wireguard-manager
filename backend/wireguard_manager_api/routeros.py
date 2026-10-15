"""RouterOS REST client with TLS verification, bounded requests, and explicit write methods."""
import ipaddress
import httpx
from .config import get_settings
from .security import decrypt_secret

class RouterConnectionError(RuntimeError):
    pass

def validate_router_host(host: str) -> str:
    """Accept IP literals only to avoid DNS rebinding and hostname-based SSRF."""
    raw = host.strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError("Router host must be an IP address; hostnames are disabled to prevent DNS rebinding") from exc
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ValueError("Loopback, link-local, multicast, reserved, and unspecified addresses are not allowed")
    if not ip.is_private and not get_settings().allow_public_router_hosts:
        raise ValueError("Public router addresses are disabled by default; enable explicitly after reviewing network egress controls")
    return str(ip)

class RouterOSClient:
    def __init__(self, host: str, port: int, username: str, encrypted_password: str, verify_tls: bool = True):
        self.host = validate_router_host(host)
        self.base_url = f"https://{self.host}:{port}/rest"
        self.username = username
        self.password = decrypt_secret(encrypted_password)
        self.verify_tls = verify_tls

    @staticmethod
    def _validate_path(path: str) -> None:
        if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("Invalid RouterOS REST path")

    async def _request(self, method: str, path: str, payload: dict | None = None) -> list[dict] | dict:
        self._validate_path(path)
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False) as client:
                response = await client.request(method, f"{self.base_url}{path}", auth=(self.username, self.password), json=payload)
                if response.status_code in (301, 302, 307, 308):
                    raise RouterConnectionError("Router returned a redirect; redirects are blocked")
                if response.status_code == 401:
                    raise RouterConnectionError("Router authentication failed")
                response.raise_for_status()
                if response.status_code == 204 or not response.content:
                    return {}
                data = response.json()
                if not isinstance(data, (list, dict)):
                    raise RouterConnectionError("Unexpected RouterOS response format")
                return data
        except RouterConnectionError:
            raise
        except httpx.HTTPError as exc:
            raise RouterConnectionError("Router request failed; check reachability, HTTPS, certificate, and account permissions") from exc

    async def get(self, path: str) -> list[dict] | dict:
        return await self._request("GET", path)

    async def post(self, path: str, payload: dict) -> dict:
        result = await self._request("POST", path, payload)
        if not isinstance(result, dict):
            raise RouterConnectionError("Unexpected RouterOS write response")
        return result

    async def patch(self, path: str, payload: dict) -> dict:
        result = await self._request("PATCH", path, payload)
        if not isinstance(result, dict):
            raise RouterConnectionError("Unexpected RouterOS write response")
        return result

    async def delete(self, path: str) -> dict:
        result = await self._request("DELETE", path)
        if not isinstance(result, dict):
            raise RouterConnectionError("Unexpected RouterOS delete response")
        return result
