"""JWT access authentication, rotating refresh sessions, and admin-only user provisioning."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .audit import record_event
from .db import get_db
from .dependencies import current_user, require_roles
from .models import RefreshSession, User
from .schemas import LoginRequest, RefreshRequest, UserCreate
from .security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
REFRESH_DAYS = 14

def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _new_refresh_token(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(48)
    db.add(RefreshSession(user_id=user.id, token_hash=_token_digest(token), expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_DAYS)))
    return token

def _token_response(db: Session, user: User, refresh_token: str) -> dict:
    return {
        "access_token": create_access_token(user.username, user.role),
        "token_type": "bearer",
        "expires_in": 60 * 15,
        "refresh_token": refresh_token,
        "refresh_expires_in": REFRESH_DAYS * 24 * 60 * 60,
        "user": {"username": user.username, "role": user.role},
    }

@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password", headers={"WWW-Authenticate": "Bearer"})
    refresh = _new_refresh_token(db, user)
    record_event(db, user.username, "auth.login", "user", str(user.id))
    db.commit()
    return _token_response(db, user, refresh)

@router.post("/refresh")
def refresh_access(body: RefreshRequest, db: Session = Depends(get_db)):
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == _token_digest(body.refresh_token)).with_for_update().first()
    now = datetime.now(timezone.utc)
    if not session or session.revoked_at is not None:
        raise HTTPException(401, "Invalid or revoked refresh token")
    expiry = session.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    user = db.get(User, session.user_id)
    if expiry <= now or not user or not user.is_active:
        session.revoked_at = now
        db.commit()
        raise HTTPException(401, "Expired session or inactive user")
    # Rotation invalidates the presented token in the same transaction.
    session.revoked_at = now
    replacement = _new_refresh_token(db, user)
    record_event(db, user.username, "auth.refresh", "user", str(user.id))
    db.commit()
    return _token_response(db, user, replacement)

@router.post("/logout", status_code=204)
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == _token_digest(body.refresh_token)).with_for_update().first()
    if session and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        user = db.get(User, session.user_id)
        if user:
            record_event(db, user.username, "auth.logout", "user", str(user.id))
        db.commit()
    return None

@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role, "is_active": user.is_active}

@router.post("/users", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), actor: User = Depends(require_roles("admin"))):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    try:
        encoded = hash_password(body.password)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    user = User(username=body.username, password_hash=encoded, role=body.role)
    db.add(user)
    db.flush()
    record_event(db, actor.username, "user.create", "user", str(user.id), details={"username": user.username, "role": user.role})
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}
