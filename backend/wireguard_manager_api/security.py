"""Password hashing, signed access tokens, and envelope encryption helpers."""
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet, InvalidToken
import jwt
from pwdlib import PasswordHash
from .config import get_settings

password_hash = PasswordHash.recommended()
ALLOWED_ROLES = {"admin", "operator", "viewer"}

def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    return password_hash.hash(password)

def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hash.verify(password, encoded)
    except Exception:
        return False

def create_access_token(username: str, role: str) -> str:
    settings = get_settings()
    if not settings.jwt_secret:
        raise RuntimeError("WGM_JWT_SECRET is not configured")
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": username, "role": role, "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)}, settings.jwt_secret, algorithm="HS256")

def decode_access_token(token: str) -> dict:
    settings = get_settings()
    if not settings.jwt_secret:
        raise RuntimeError("WGM_JWT_SECRET is not configured")
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], options={"require": ["sub", "exp", "iat"]})

def _fernet() -> Fernet:
    key = get_settings().encryption_key
    if not key:
        raise RuntimeError("WGM_ENCRYPTION_KEY is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("WGM_ENCRYPTION_KEY must be a valid Fernet key") from exc

def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()

def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Stored secret cannot be decrypted; verify encryption key and backup") from exc
