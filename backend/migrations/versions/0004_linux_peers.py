"""Add Linux WireGuard peer inventory."""
from alembic import op
import sqlalchemy as sa
revision = "0004_linux_peers"
down_revision = "0003_linux_servers"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("linux_peers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("linux_servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("interface_name", sa.String(120), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("private_key_ciphertext", sa.Text(), nullable=True),
        sa.Column("allowed_address", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("public_key", name="uq_linux_peers_public_key"))
    op.create_index("ix_linux_peers_server_id", "linux_peers", ["server_id"])

def downgrade() -> None:
    op.drop_index("ix_linux_peers_server_id", table_name="linux_peers")
    op.drop_table("linux_peers")
