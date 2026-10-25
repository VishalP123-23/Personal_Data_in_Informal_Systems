"""Track pending second review for partial erasure decisions."""
from alembic import op
import sqlalchemy as sa

revision = "0006_rights_request_followup"
down_revision = "0005_encrypt_categories"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("rights_requests", sa.Column("pending_erasure_categories", sa.Text(), nullable=True))
    op.add_column("rights_requests", sa.Column("follow_up_due_at", sa.DateTime(timezone=True), nullable=True))

def downgrade():
    op.drop_column("rights_requests", "follow_up_due_at")
    op.drop_column("rights_requests", "pending_erasure_categories")
