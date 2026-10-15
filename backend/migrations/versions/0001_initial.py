"""Initial schema for users, routers, peers, and audit events."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table("routers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(120), nullable=False),
        sa.Column("credential_ciphertext", sa.Text(), nullable=False),
        sa.Column("tls_verify", sa.Boolean(), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("peers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("router_id", sa.Integer(), sa.ForeignKey("routers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("router_peer_id", sa.String(120), nullable=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("private_key_ciphertext", sa.Text(), nullable=True),
        sa.Column("allowed_address", sa.String(64), nullable=False),
        sa.Column("endpoint", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("public_key", name="uq_peers_public_key"))
    op.create_index("ix_peers_router_id", "peers", ["router_id"])
    op.create_table("audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_username", sa.String(80), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(120), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_audit_events_actor_username", "audit_events", ["actor_username"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_event_hash", "audit_events", ["event_hash"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])

def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_index("ix_peers_router_id", table_name="peers")
    op.drop_table("peers")
    op.drop_table("routers")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
