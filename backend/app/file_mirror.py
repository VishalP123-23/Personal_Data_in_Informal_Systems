"""Local appointment file mirror; PostgreSQL remains the source of truth."""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from sqlalchemy import event, select
from sqlalchemy.orm import Session
from .data_protection import encrypt_personal_data

OUTPUT = Path(__file__).resolve().parents[2] / "data" / "appointments.json"
_lock = RLock()

def write_snapshot(engine, output=OUTPUT):
    from .models import Appointment, User
    with _lock:
        with Session(engine) as db:
            records = []
            rows = db.scalars(select(Appointment)).all()
            rows.sort(key=lambda row: row.starts_at.replace(tzinfo=row.starts_at.tzinfo or timezone.utc))
            for row in rows:
                patient = db.get(User, row.patient_id)
                provider = db.get(User, row.provider_id) if row.provider_id else None
                records.append({"id": row.id, "patient_name": patient.display_name if patient else None,
                    "provider_name": provider.display_name if provider else "Unassigned",
                    "starts_at": row.starts_at.isoformat(), "ends_at": row.ends_at.isoformat(),
                    "status": row.status, "reason": row.reason_minimised, "created_at": row.created_at.isoformat()})
        payload = {"source": "Local PostgreSQL: clinic_privacy / appointments",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "note": "Automatically refreshed after application database commits. Appointment details are encrypted with the local personal-data key; PostgreSQL is the source of truth. Do not edit this generated file.",
            "count": len(records),
            "encrypted_appointments": encrypt_personal_data(json.dumps(records, ensure_ascii=False, separators=(",", ":")), "export.appointments")}
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, output)
        return len(records)

def write_patient_count(engine, output=None):
    """Write aggregate-only patient counts for VS Code; never export identifying details."""
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session
    from .models import User, Appointment, ConsentRecord, ClinicalNote, Prescription, RightsRequest, PatientComplaint
    output = Path(output) if output else Path(__file__).resolve().parents[2] / "data" / "patient_count.json"
    with Session(engine) as db:
        patients = db.scalar(select(func.count()).select_from(User).where(User.role == "patient", User.is_active.is_(True))) or 0
        tombstones = db.scalar(select(func.count()).select_from(User).where(User.role == "patient", User.is_active.is_(False))) or 0
        categories = {
            "appointments": Appointment,
            "consent_records": ConsentRecord,
            "clinical_notes": ClinicalNote,
            "prescriptions": Prescription,
            "rights_requests": RightsRequest,
            "complaints": PatientComplaint,
        }
        records = {name: db.scalar(select(func.count()).select_from(model).join(
            User, model.patient_id == User.id).where(User.role == "patient", User.is_active.is_(True))) or 0
                   for name, model in categories.items()}
    payload = {
        "source": "Local PostgreSQL: clinic_privacy",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "active_patient_count": patients,
        "inactive_erased_profiles": tombstones,
        "active_patient_linked_records": records,
        "note": "Aggregate counts only. Readable patient details are available only in the authenticated security-admin Patient register. PostgreSQL remains the source of truth.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, output)

def install_mirror(factory, engine, output=OUTPUT):
    def committed(session):
        try:
            write_snapshot(engine, output)
            write_patient_count(engine, Path(output).parent / "patient_count.json")
        except Exception:
            # A file lock must not turn an already committed database write into a failed API response.
            logging.getLogger(__name__).exception("Database saved, but appointment file refresh failed")
    event.listen(factory, "after_commit", committed)
