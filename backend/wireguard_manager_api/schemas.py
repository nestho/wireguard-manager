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
    tls_verify: bool = True\n    @field_validator("tls_verify")\n    @classmethod\n    def tls_must_be_verified(cls, value: bool) -> bool:\n        if value is not True:\n            raise ValueError("TLS certificate verification cannot be disabled")\n        return value

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
    name: str = Field(min_length=1, max_length=120)
    allowed_address: str = Field(min_length=3, max_length=64)
    endpoint: str | None = Field(default=None, max_length=255)
    confirm: bool = False
    dry_run: bool = True

class UserView(BaseModel):
    username: str
    role: str
    is_active: bool
