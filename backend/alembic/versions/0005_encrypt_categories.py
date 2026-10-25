"""Encrypt user-controlled complaint and incident labels."""
from alembic import op
from sqlalchemy import inspect, text, Text
from app.data_protection import encrypt_personal_data

revision = "0005_encrypt_categories"
down_revision = "0004_encrypt_appt_dates"
branch_labels = None
depends_on = None

COLUMNS = {
    "incident_actions": {"action": "incident_action.action"},
    "patient_complaints": {"category": "patient_complaint.category"},
}


def upgrade():
    connection = op.get_bind()
    for table, columns in COLUMNS.items():
        existing = {column["name"]: column for column in inspect(connection).get_columns(table)}
        for name in columns:
            column = existing[name]
            if not isinstance(column["type"], Text):
                op.alter_column(table, name, type_=Text(), existing_type=column["type"])
        names = list(columns)
        rows = connection.execute(text(f"SELECT id, {', '.join(names)} FROM {table}")).mappings().all()
        for row in rows:
            values = {name: (row[name] if isinstance(row[name], str) and row[name].startswith("enc:v1:") else encrypt_personal_data(row[name], context)) for name, context in columns.items()}
            assignments = ", ".join(f"{name} = :{name}" for name in values)
            connection.execute(text(f"UPDATE {table} SET {assignments} WHERE id = :id"), {**values, "id": row["id"]})


def downgrade():
    raise RuntimeError("Downgrade is disabled because it would restore personal data in plaintext")
