"""Store per-peer destination ACLs for RouterOS and Linux peers."""
from alembic import op
import sqlalchemy as sa

revision = "0005_peer_access_control"
down_revision = "0004_linux_peers"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("peers", sa.Column("access_networks_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("linux_peers", sa.Column("access_networks_json", sa.Text(), nullable=False, server_default="[]"))

def downgrade() -> None:
    op.drop_column("linux_peers", "access_networks_json")
    op.drop_column("peers", "access_networks_json")
