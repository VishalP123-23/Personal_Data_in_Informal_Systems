from datetime import timedelta
from sqlalchemy import select
from .db import SessionLocal
from .models import User, PrivacyNotice, RetentionPolicy, ClinicalNote, Prescription, Appointment, ErasureAction, utcnow
from .security import hash_password
from .data_protection import personal_data_hash

ACCOUNTS = [
    ("demo.patient", "PatientDemo#2026", "patient", "Aarav Demo", "demo-patient@example.invalid"),
    ("demo.reception", "ReceptionDemo#2026", "receptionist", "Mira Reception", None),
    ("demo.doctor", "DoctorDemo#2026", "doctor", "Dr. Neel Demo", None),
    ("demo.privacy", "PrivacyDemo#2026", "privacy_officer", "Isha Privacy", None),
    ("demo.security", "SecurityDemo#2026", "security_admin", "Kabir Security", None),
]
NOTICE = ("demo-v3", "This is a hackathon demonstration using synthetic data only. The clinic processes profile, appointment, and demo clinical information to provide and manage care. Patient records remain in the local demo database. Optional reminders are separate and can be withdrawn. You may request access, correction, erasure, or privacy complaint requests through this portal. Some records may need to be retained under applicable obligations; retention rules must be verified before real use. Contact the clinic privacy officer through the in-person desk.")
POLICIES = [
    ("registration_contact", "Review and delete when the operational purpose ends unless another verified obligation applies.", "purpose completion"),
    ("appointments", "Review cancelled and completed scheduling data under clinic policy; legal basis not verified.", "appointment completion"),
    ("clinical_notes", "Retention period requires clinic/legal review for the applicable record category.", "last consultation or applicable trigger"),
    ("prescriptions", "Retention period requires clinic/legal review for the applicable record category.", "issue date or applicable trigger"),
    ("billing", "Retention period requires finance/legal review.", "financial record creation"),
    ("cctv", "No CCTV ingestion is implemented in this demo. If footage is collected for a defined lawful security purpose, minimize clips, encrypt stored video, restrict and log access, and set a verified deletion schedule. Footage may include patients, staff, visitors, and bystanders; do not attach a full CCTV history to a patient profile by default.", "capture or incident date; retention schedule requires review"),
    ("consent_logs", "Retain only as needed to evidence choices and satisfy verified obligations.", "consent event"),
    ("complaints", "Retention period requires legal review; minimize details and restrict access.", "closure date"),
    ("incidents", "Retention period requires security/legal review.", "incident closure"),
    ("application_logs", "Minimize and periodically review; never store secrets or full clinical content.", "log creation"),
    ("backups", "Documented expiry and restoration testing required; this demo does not configure backups.", "backup creation"),
]

def main():
    db = SessionLocal()
    try:
        users = {}
        for username, password, role, name, contact in ACCOUNTS:
            user = db.scalar(select(User).where(User.username_digest == personal_data_hash(username, "user.username")))
            if not user and role == "patient":
                # Keep the synthetic account erased after an approved profile erasure.
                erased_action = db.scalar(select(ErasureAction).where(
                    ErasureAction.entity_type == "profile",
                    ErasureAction.action == "deactivated_and_scrubbed").limit(1))
                if erased_action:
                    user = db.get(User, erased_action.entity_id)
            if not user:
                user = User(username=username, password_hash=hash_password(password), role=role,
                            display_name=name, contact_value=contact)
                db.add(user)
            users[role] = user
        db.flush()
        notices = db.scalars(select(PrivacyNotice)).all()
        existing_versions = {notice.version for notice in notices}
        for notice in notices:
            notice.active = notice.version == NOTICE[0]
        if NOTICE[0] not in existing_versions:
            db.add(PrivacyNotice(version=NOTICE[0], language="en", notice_text=NOTICE[1], active=True))
        for category, description, trigger in POLICIES:
            policy = db.scalar(select(RetentionPolicy).where(RetentionPolicy.data_category == category))
            if not policy:
                db.add(RetentionPolicy(data_category=category, rule_description=description,
                                       retention_trigger=trigger, duration_days=None, verified=False))
            elif category == "cctv" and not policy.verified:
                policy.rule_description = description
                policy.retention_trigger = trigger
                policy.duration_days = None
        patient, doctor = users["patient"], users["doctor"]
        db.flush()
        if patient.is_active and not db.scalar(select(ClinicalNote).where(ClinicalNote.patient_id == patient.id)):
            db.add(ClinicalNote(patient_id=patient.id, doctor_id=doctor.id,
                                note_text="Synthetic demo note: routine follow-up discussed. No real patient information.",
                                visibility_status="released", retention_class="review_required"))
            db.add(Prescription(patient_id=patient.id, doctor_id=doctor.id,
                                instructions="Synthetic demo prescription: sample medication instructions only. Not medical advice.",
                                visibility_status="released", retention_class="review_required"))
            start = utcnow() + timedelta(days=2)
            start = start.replace(hour=10, minute=0, second=0, microsecond=0)
            db.add(Appointment(patient_id=patient.id, provider_id=doctor.id, starts_at=start,
                               ends_at=start + timedelta(minutes=30), status="scheduled",
                               reason_minimised="Routine follow-up"))
        db.commit()
    finally:
        db.close()

if __name__ == "__main__":
    main()
