"""Operational setup and audit verification endpoints."""
import hashlib, json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from .db import get_db
from .dependencies import require_roles
from .models import AuditEvent, User
from .security import hash_password
from .config import get_settings
from sqlalchemy import select

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])
@router.post("/bootstrap", status_code=201)
def bootstrap_admin(db: Session = Depends(get_db)):
    settings = get_settings()
    if not settings.bootstrap_admin_username or not settings.bootstrap_admin_password:
        raise HTTPException(404, "Bootstrap is disabled; configure bootstrap credentials before first start")
    if db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(409, "Bootstrap is only available before the first user exists")
    try:
        encoded = hash_password(settings.bootstrap_admin_password)
    except ValueError as exc:
        raise HTTPException(500, "Bootstrap password does not meet the configured policy") from exc
    user = User(username=settings.bootstrap_admin_username, password_hash=encoded, role="admin")
    db.add(user)
    db.commit()
    return {"username": user.username, "role": user.role, "message": "Remove bootstrap credentials from the environment after setup"}

@router.get("/audit")
def list_audit_events(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).offset(offset).limit(limit)).all()
    return [{
        "id": event.id,
        "actor": event.actor_username,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome,
        "details": json.loads(event.details_json or "{}"),
        "created_at": event.created_at.isoformat(),
        "event_hash": event.event_hash,
        "previous_hash": event.previous_hash,
    } for event in events]


@router.get("/audit/verify")
def verify_audit_chain(db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
    previous = "0" * 64
    for event in events:
        payload = {"actor": event.actor_username, "action": event.action, "target_type": event.target_type, "target_id": event.target_id, "outcome": event.outcome, "details": json.loads(event.details_json or "{}"), "previous_hash": previous}
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if event.previous_hash != previous or event.event_hash != expected:
            return {"valid": False, "first_invalid_event_id": event.id, "checked": events.index(event)}
        previous = event.event_hash
    return {"valid": True, "checked": len(events)}
