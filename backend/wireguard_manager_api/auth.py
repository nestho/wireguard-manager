"""JWT access authentication and admin-only user provisioning."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .audit import record_event
from .db import get_db
from .dependencies import current_user, require_roles
from .models import User
from .schemas import LoginRequest, UserCreate
from .security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password", headers={"WWW-Authenticate": "Bearer"})
    record_event(db, user.username, "auth.login", "user", str(user.id))
    db.commit()
    return {"access_token": create_access_token(user.username, user.role), "token_type": "bearer", "expires_in": 60 * 15, "user": {"username": user.username, "role": user.role}}

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
