"""Append-only hash-linked audit events; database administrators can still rewrite the chain."""
import hashlib, json
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import AuditEvent

def record_event(db: Session, actor: str, action: str, target_type: str, target_id: str, outcome: str = "success", details: dict | None = None) -> AuditEvent:
    previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    previous_hash = previous.event_hash if previous else "0" * 64
    payload = {"actor": actor, "action": action, "target_type": target_type, "target_id": target_id, "outcome": outcome, "details": details or {}, "previous_hash": previous_hash}
    event_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    event = AuditEvent(actor_username=actor, action=action, target_type=target_type, target_id=target_id, outcome=outcome, details_json=json.dumps(details or {}, sort_keys=True), previous_hash=previous_hash, event_hash=event_hash)
    db.add(event)
    db.flush()
    return event
