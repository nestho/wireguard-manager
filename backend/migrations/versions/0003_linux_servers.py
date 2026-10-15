"""Add Linux server inventory."""
from alembic import op
import sqlalchemy as sa

revision = "0003_linux_servers"
down_revision = "0002_refresh_sessions"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("linux_servers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(120), nullable=False),
        sa.Column("private_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("host_key_fingerprint", sa.String(128), nullable=False),
        sa.Column("distro_id", sa.String(80), nullable=True),
        sa.Column("distro_version", sa.String(80), nullable=True),
        sa.Column("package_manager", sa.String(40), nullable=True),
        sa.Column("wireguard_installed", sa.Boolean(), nullable=False),
        sa.Column("last_status", sa.String(24), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_linux_servers_host", "linux_servers", ["host"])

def downgrade() -> None:
    op.drop_index("ix_linux_servers_host", table_name="linux_servers")
    op.drop_table("linux_servers")
