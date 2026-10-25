"""Widen encrypted columns and protect remaining incident metadata."""
from alembic import op
from sqlalchemy import inspect, text, Text
from app.data_protection import encrypt_personal_data

revision = "0003_protect_fields"
down_revision = "0002_protect_personal_data"
branch_labels = None
depends_on = None

PROTECTED_COLUMNS = {
    "security_incidents": {"source": "security_incident.source", "affected_categories": "security_incident.affected_categories"},
    "incident_notifications": {"method": "incident_notification.method", "evidence_ref": "incident_notification.evidence_ref"},
}


def upgrade():
    connection = op.get_bind()
    for table, columns in PROTECTED_COLUMNS.items():
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

    # Version 0002 may have run before the VARCHAR widening was added; ensure every protected field can hold ciphertext.
    widened_columns = {
        "users": ("username", "display_name", "contact_value"),
        "appointments": ("reason_minimised",),
        "clinical_notes": ("note_text",),
        "prescriptions": ("instructions",),
        "rights_requests": ("description", "decision", "legal_basis_note"),
        "erasure_actions": ("reason",),
        "security_incidents": ("source", "affected_categories", "summary", "containment", "impact_assessment", "closure_summary"),
        "incident_actions": ("note",),
        "incident_notifications": ("method", "evidence_ref"),
        "patient_complaints": ("description", "resolution_summary"),
        "complaint_updates": ("message",),
        "audit_events": ("reason", "request_id", "metadata_minimised"),
    }
    for table, columns in widened_columns.items():
        existing = {column["name"]: column for column in inspect(connection).get_columns(table)}
        for name in columns:
            column = existing[name]
            if not isinstance(column["type"], Text):
                op.alter_column(table, name, type_=Text(), existing_type=column["type"])


def downgrade():
    raise RuntimeError("Downgrade is disabled because it would restore personal data in plaintext")
