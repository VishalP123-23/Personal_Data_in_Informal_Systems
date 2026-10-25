"""Encrypt existing personal data and add keyed identity digests."""
from alembic import op
from sqlalchemy import Column, String, Text, inspect, text
from app.data_protection import encrypt_personal_data, personal_data_hash

revision = "0002_protect_personal_data"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

PROTECTED_COLUMNS = {
    "users": {"username": "user.username", "display_name": "user.display_name", "contact_value": "user.contact_value"},
    "appointments": {"reason_minimised": "appointment.reason_minimised"},
    "clinical_notes": {"note_text": "clinical_note.note_text"},
    "prescriptions": {"instructions": "prescription.instructions"},
    "rights_requests": {"description": "rights_request.description", "decision": "rights_request.decision", "legal_basis_note": "rights_request.legal_basis_note"},
    "erasure_actions": {"reason": "erasure_action.reason"},
    "security_incidents": {"source": "security_incident.source", "affected_categories": "security_incident.affected_categories", "summary": "security_incident.summary", "containment": "security_incident.containment", "impact_assessment": "security_incident.impact_assessment", "closure_summary": "security_incident.closure_summary"},
    "incident_notifications": {"method": "incident_notification.method", "evidence_ref": "incident_notification.evidence_ref"},
    "incident_actions": {"note": "incident_action.note"},
    "patient_complaints": {"description": "patient_complaint.description", "resolution_summary": "patient_complaint.resolution_summary"},
    "complaint_updates": {"message": "complaint_update.message"},
    "audit_events": {"reason": "audit_event.reason", "request_id": "audit_event.request_id", "metadata_minimised": "audit_event.metadata_minimised"},
}


def upgrade():
    connection = op.get_bind()
    # Ciphertext is longer than the original bounded VARCHAR fields.
    for table, columns in PROTECTED_COLUMNS.items():
        existing_columns = {column["name"]: column for column in inspect(connection).get_columns(table)}
        for name in columns:
            column = existing_columns[name]
            if not isinstance(column["type"], Text):
                op.alter_column(table, name, type_=Text(), existing_type=column["type"])
    existing = {column["name"] for column in inspect(connection).get_columns("users")}
    for name in ("username_digest", "display_name_digest", "contact_digest"):
        if name not in existing:
            op.add_column("users", Column(name, String(72), nullable=True))
    inspector = inspect(connection)
    has_digest_index = any(index["name"] == "ix_users_username_digest" for index in inspector.get_indexes("users"))
    has_digest_constraint = any(constraint.get("column_names") == ["username_digest"] for constraint in inspector.get_unique_constraints("users"))
    if not has_digest_index and not has_digest_constraint:
        op.create_index("ix_users_username_digest", "users", ["username_digest"], unique=True)
    for table, columns in PROTECTED_COLUMNS.items():
        names = list(columns)
        rows = connection.execute(text(f"SELECT id, {', '.join(names)} FROM {table}")).mappings().all()
        for row in rows:
            values = {name: (row[name] if isinstance(row[name], str) and row[name].startswith("enc:v1:") else encrypt_personal_data(row[name], context)) for name, context in columns.items()}
            if table == "users":
                values["username_digest"] = personal_data_hash(row["username"], "user.username")
                values["display_name_digest"] = personal_data_hash(row["display_name"], "user.display_name")
                values["contact_digest"] = personal_data_hash(row["contact_value"], "user.contact_value")
            assignments = ", ".join(f"{name} = :{name}" for name in values)
            connection.execute(text(f"UPDATE {table} SET {assignments} WHERE id = :id"), {**values, "id": row["id"]})


def downgrade():
    raise RuntimeError("Downgrade is disabled because it would restore personal data in plaintext")
