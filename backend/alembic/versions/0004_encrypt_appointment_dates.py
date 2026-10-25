"""Encrypt appointment timestamps stored in the database."""
from alembic import op
from sqlalchemy import inspect, text, Text
from app.data_protection import encrypt_personal_data

revision = "0004_encrypt_appt_dates"
down_revision = "0003_protect_fields"
branch_labels = None
depends_on = None

COLUMNS = {
    "starts_at": "appointment.starts_at",
    "ends_at": "appointment.ends_at",
    "created_at": "appointment.created_at",
}


def upgrade():
    connection = op.get_bind()
    existing = {column["name"]: column for column in inspect(connection).get_columns("appointments")}
    for name in COLUMNS:
        column = existing[name]
        if not isinstance(column["type"], Text):
            op.alter_column("appointments", name, type_=Text(), existing_type=column["type"],
                            postgresql_using=f"{name}::text")
    rows = connection.execute(text("SELECT id, starts_at, ends_at, created_at FROM appointments")).mappings().all()
    for row in rows:
        values = {}
        for name, context in COLUMNS.items():
            value = row[name]
            values[name] = value if isinstance(value, str) and value.startswith("enc:v1:") else encrypt_personal_data(value.isoformat() if hasattr(value, "isoformat") else str(value), context)
        connection.execute(text("UPDATE appointments SET starts_at=:starts_at, ends_at=:ends_at, created_at=:created_at WHERE id=:id"), {**values, "id": row["id"]})
    if any(index["name"] == "ix_appointments_starts_at" for index in inspect(connection).get_indexes("appointments")):
        op.drop_index("ix_appointments_starts_at", table_name="appointments")


def downgrade():
    raise RuntimeError("Downgrade is disabled because it would restore personal data in plaintext")
