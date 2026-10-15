"""Request/response schemas. Secret fields are never included in response models."""
from pydantic import BaseModel, Field, field_validator

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str = "viewer"
    @field_validator("role")
    @classmethod
    def role_valid(cls, value: str) -> str:
        if value not in {"admin", "operator", "viewer"}:
            raise ValueError("Role must be admin, operator, or viewer")
        return value

class RouterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    tls_verify: bool = True

    @field_validator("tls_verify")
    @classmethod
    def tls_must_be_verified(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("TLS certificate verification cannot be disabled")
        return value

class RouterView(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    tls_verify: bool
    last_status: str
    created_at: str

class PeerCreate(BaseModel):
    interface_name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=120)
    allowed_address: str = Field(min_length=3, max_length=64)
    endpoint: str | None = Field(default=None, max_length=255)
    confirm: bool = False
    dry_run: bool = True

class UserView(BaseModel):
    username: str
    role: str
    is_active: bool

class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=40, max_length=256)

class ClientConfigRequest(BaseModel):
    server_public_key: str = Field(min_length=44, max_length=44)
    endpoint: str = Field(min_length=3, max_length=255)
    dns: str = Field(default="1.1.1.1", min_length=1, max_length=255)
    allowed_ips: str = Field(default="0.0.0.0/0, ::/0", min_length=1, max_length=512)
    persistent_keepalive: int = Field(default=25, ge=0, le=65535)

    @field_validator("server_public_key")
    @classmethod
    def valid_server_key(cls, value: str) -> str:
        import base64
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise ValueError("server_public_key must be base64-encoded WireGuard key material") from exc
        if len(decoded) != 32:
            raise ValueError("server_public_key must decode to exactly 32 bytes")
        return value

    @field_validator("endpoint")
    @classmethod
    def valid_endpoint(cls, value: str) -> str:
        import re
        if not re.fullmatch(r"[A-Za-z0-9.:[\]-]+:[0-9]{1,5}", value):
            raise ValueError("endpoint must be a host or IP and port, e.g. vpn.example.com:51820")
        port = int(value.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        return value

    @field_validator("dns")
    @classmethod
    def valid_dns(cls, value: str) -> str:
        import ipaddress
        for server in value.split(","):
            try:
                ipaddress.ip_address(server.strip())
            except ValueError as exc:
                raise ValueError("dns must be a comma-separated list of IP addresses") from exc
        return ", ".join(part.strip() for part in value.split(","))

    @field_validator("allowed_ips")
    @classmethod
    def valid_allowed_ips(cls, value: str) -> str:
        import ipaddress
        try:
            networks = [str(ipaddress.ip_network(part.strip(), strict=False)) for part in value.split(",")]
        except ValueError as exc:
            raise ValueError("allowed_ips must be a comma-separated list of valid IP networks") from exc
        if not networks:
            raise ValueError("At least one allowed IP network is required")
        return ", ".join(networks)
