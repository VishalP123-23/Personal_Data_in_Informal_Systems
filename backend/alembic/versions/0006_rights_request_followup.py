"""Track pending second review for partial erasure decisions."""
from alembic import op
import sqlalchemy as sa

revision = "0006_rights_request_followup"
down_revision = "0005_encrypt_categories"
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    cols = {c["name"] for c in sa.inspect(conn).get_columns("rights_requests")}
    if "pending_erasure_categories" not in cols:
        op.add_column("rights_requests", sa.Column("pending_erasure_categories", sa.Text(), nullable=True))
    if "follow_up_due_at" not in cols:
        op.add_column("rights_requests", sa.Column("follow_up_due_at", sa.DateTime(timezone=True), nullable=True))

def downgrade():
    conn = op.get_bind()
    cols = {c["name"] for c in sa.inspect(conn).get_columns("rights_requests")}
    if "follow_up_due_at" in cols:
        op.drop_column("rights_requests", "follow_up_due_at")
    if "pending_erasure_categories" in cols:
        op.drop_column("rights_requests", "pending_erasure_categories")
