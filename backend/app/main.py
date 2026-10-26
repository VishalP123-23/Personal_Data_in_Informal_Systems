import json
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, or_, func, delete
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from . import models as m
from .schemas import (LoginIn, RegisterIn, ProfileUpdateIn, ConsentIn, AppointmentIn, RequestIn, ReviewIn,
                      ComplaintIn, ComplaintUpdateIn, IncidentIn, IncidentActionIn, ErasureReceiptLookupIn,
                      ClinicalNoteIn, PrescriptionIn)
from .security import hash_password, verify_password, new_token, token_hash
from .data_protection import personal_data_hash, mask_contact_value

app = FastAPI(title="Clinic Patient Privacy", version="0.1.0", description="Local synthetic-data hackathon demo")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
                   allow_origin_regex=r"https://.*\.vercel\.app" if settings.app_env != "local-demo" else None,
                   allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
                   allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
                   expose_headers=["X-CSRF-Token", "X-Request-ID"])

attempts = defaultdict(deque)
COOKIE_NAME = "clinic_session"
CSRF_COOKIE = "clinic_csrf"


def now_utc():
    return datetime.now(timezone.utc)


def normalize_dt(value: datetime):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def to_iso(value):
    return normalize_dt(value).isoformat() if value else None


def audit(db: Session, actor_id, action, entity_type, entity_id=None, request=None,
          reason=None, outcome="success", meta=None):
    db.add(m.AuditEvent(actor_id=actor_id, action=action, entity_type=entity_type,
                        entity_id=entity_id, request_id=request.headers.get("X-Request-ID") if request else None,
                        reason=reason[:240] if reason else None, outcome=outcome,
                        metadata_minimised=json.dumps(meta or {}, separators=(",", ":"))))


def user_out(user):
    return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role}


def appointment_out(a, db):
    patient = db.get(m.User, a.patient_id)
    provider = db.get(m.User, a.provider_id) if a.provider_id else None
    return {"id": a.id, "patient_id": a.patient_id, "patient_name": patient.display_name if patient else "Patient",
            "provider_id": a.provider_id, "provider_name": provider.display_name if provider else "Unassigned",
            "starts_at": to_iso(a.starts_at), "ends_at": to_iso(a.ends_at), "status": a.status,
            "reason_minimised": a.reason_minimised, "created_at": to_iso(a.created_at)}


def erasure_receipt_token(r):
    return personal_data_hash(f"{r.id}:{r.patient_id}", "erasure_receipt")


def request_out(r, staff_view=False, patient_view=False):
    return {"id": r.id, "request_type": r.request_type, "description": r.description, "status": r.status,
            "submitted_at": to_iso(r.submitted_at), "decision": r.decision,
            "pending_erasure_categories": json.loads(r.pending_erasure_categories or "[]"),
            "follow_up_due_at": to_iso(r.follow_up_due_at),
            **({"receipt_token": erasure_receipt_token(r)} if patient_view and r.request_type == "full_erasure" else {}),
            **({"legal_basis_note": r.legal_basis_note} if staff_view else {}),
            "completed_at": to_iso(r.completed_at), "patient_id": r.patient_id}


def complaint_out(c, db, patient_view=False):
    updates = db.scalars(select(m.ComplaintUpdate).where(m.ComplaintUpdate.complaint_id == c.id)
                         .order_by(m.ComplaintUpdate.created_at)).all()
    patient = db.get(m.User, c.patient_id)
    return {"id": c.id, "patient_id": c.patient_id, "patient_name": patient.display_name if patient else "Patient",
            "category": c.category, "description": c.description, "status": c.status, "priority": c.priority,
            "submitted_at": to_iso(c.submitted_at), "resolved_at": to_iso(c.resolved_at),
            "resolution_summary": c.resolution_summary,
            "updates": [{"id": u.id, "message": u.message, "visibility": u.visibility,
                         "created_at": to_iso(u.created_at)} for u in updates if not patient_view or u.visibility == "patient"]}


def incident_out(i, db):
    actions = db.scalars(select(m.IncidentAction).where(m.IncidentAction.incident_id == i.id)
                         .order_by(m.IncidentAction.occurred_at)).all()
    notifications = db.scalars(select(m.IncidentNotification).where(m.IncidentNotification.incident_id == i.id)).all()
    return {"id": i.id, "detected_at": to_iso(i.detected_at), "severity": i.severity, "status": i.status,
            "source": i.source, "summary": i.summary, "affected_categories": json.loads(i.affected_categories or "[]"),
            "containment": i.containment, "impact_assessment": i.impact_assessment,
            "closure_summary": i.closure_summary,
            "actions": [{"id": a.id, "action": a.action, "note": a.note, "occurred_at": to_iso(a.occurred_at)} for a in actions],
            "notifications": [{"recipient_type": n.recipient_type, "decision": n.decision,
                               "reviewed_at": to_iso(n.sent_at), "method": n.method} for n in notifications]}


def current_user(request: Request, db: Session = Depends(get_db)):
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(401, "Sign in required")
    session = db.get(m.LoginSession, token_hash(raw))
    if not session or normalize_dt(session.expires_at) <= now_utc():
        raise HTTPException(401, "Session expired")
    user = db.get(m.User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    return user


def require_roles(*allowed):
    def check(user: m.User = Depends(current_user)):
        if user.role not in allowed:
            raise HTTPException(403, "You do not have access to this action")
        return user
    return check


@app.middleware("http")
async def protect_cookie_writes(request: Request, call_next):
    if request.method in {"POST", "PATCH", "PUT", "DELETE"} and request.url.path not in {"/api/auth/login", "/api/auth/register"}:
        if request.cookies.get(COOKIE_NAME):
            supplied = request.headers.get("X-CSRF-Token", "")
            cookie = request.cookies.get(CSRF_COOKIE, "")
            if not supplied or not cookie or not secrets.compare_digest(supplied, cookie):
                return Response(content='{"detail":"CSRF token missing or invalid"}', status_code=403,
                                media_type="application/json")
    response = await call_next(request)
    return response


@app.get("/api/health")
def health():
    return {"status": "ok", "environment": settings.app_env, "demo_only": True}


@app.get("/api/privacy-notice")
def get_notice(db: Session = Depends(get_db)):
    notice = db.scalar(select(m.PrivacyNotice).where(m.PrivacyNotice.active.is_(True)).order_by(m.PrivacyNotice.effective_at.desc()))
    if not notice:
        return {"version": "demo-v3", "language": "en", "notice_text": "This is a hackathon demonstration using synthetic data only. Patient records remain in the local demo database. Optional reminders are separate. You may submit access, correction, erasure, or privacy complaint requests through this portal. Retention rules must be verified before real use."}
    return {"version": notice.version, "language": notice.language, "notice_text": notice.notice_text}


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if not payload.notice_acknowledged:
        raise HTTPException(400, "Please review the demo privacy notice")
    if db.scalar(select(m.User).where(m.User.username_digest == personal_data_hash(payload.username, "user.username"))):
        raise HTTPException(409, "That username is already in use")
    user = m.User(username=payload.username, password_hash=hash_password(payload.password), role="patient",
                  display_name=payload.display_name.strip(), contact_value=payload.contact_value)
    db.add(user)
    db.flush()
    audit(db, user.id, "patient.register", "user", user.id, request)
    db.commit()
    return user_out(user)


@app.post("/api/auth/login")
def login(payload: LoginIn, response: Response, request: Request, db: Session = Depends(get_db)):
    key = (request.client.host if request.client else "local", payload.username.lower())
    recent = attempts[key]
    cutoff = now_utc() - timedelta(minutes=10)
    while recent and recent[0] < cutoff:
        recent.popleft()
    if len(recent) >= 8:
        raise HTTPException(429, "Too many sign-in attempts. Try again later.")
    user = db.scalar(select(m.User).where(m.User.username_digest == personal_data_hash(payload.username, "user.username")))
    if not user or not verify_password(payload.password, user.password_hash) or not user.is_active:
        recent.append(now_utc())
        audit(db, user.id if user else None, "auth.login_failed", "user", user.id if user else None,
              request, outcome="denied")
        db.commit()
        raise HTTPException(401, "Username or password is incorrect")
    recent.clear()
    return issue_login_session(user, response, request, db)


def issue_login_session(user, response, request, db):
    raw = new_token()
    csrf = new_token()
    expires = now_utc() + timedelta(hours=settings.session_ttl_hours)
    db.add(m.LoginSession(id=token_hash(raw), user_id=user.id, csrf_token=csrf, expires_at=expires))
    user.last_login_at = now_utc()
    audit(db, user.id, "auth.login", "user", user.id, request)
    db.commit()
    response.set_cookie(COOKIE_NAME, raw, httponly=True, secure=settings.cookie_secure,
                        samesite=settings.cookie_samesite, max_age=settings.session_ttl_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.cookie_secure,
                        samesite=settings.cookie_samesite, max_age=settings.session_ttl_hours * 3600, path="/")
    response.headers["X-CSRF-Token"] = csrf
    return user_out(user)


@app.post("/api/auth/logout")
def logout(response: Response, request: Request, user: m.User = Depends(current_user), db: Session = Depends(get_db)):
    raw = request.cookies.get(COOKIE_NAME)
    session = db.get(m.LoginSession, token_hash(raw)) if raw else None
    if session:
        db.delete(session)
    audit(db, user.id, "auth.logout", "user", user.id, request)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/", secure=settings.cookie_secure, httponly=True, samesite=settings.cookie_samesite)
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.cookie_secure, samesite=settings.cookie_samesite)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: m.User = Depends(current_user)):
    return user_out(user)


@app.get("/api/patient/profile")
def patient_profile(user: m.User = Depends(require_roles("patient"))):
    return {"id": user.id, "display_name": user.display_name, "username": user.username,
            "contact_value": user.contact_value, "created_at": to_iso(user.created_at)}


@app.patch("/api/patient/profile")
def update_profile(payload: ProfileUpdateIn, request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    name = payload.display_name
    contact = payload.contact_value
    if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 120):
        raise HTTPException(422, "Display name must be 1-120 characters")
    if contact is not None and (not isinstance(contact, str) or len(contact) > 120):
        raise HTTPException(422, "Contact field is too long")
    if "display_name" in payload.model_fields_set and name is not None:
        user.display_name = name.strip()
    if "contact_value" in payload.model_fields_set:
        user.contact_value = contact.strip() if contact else None
    audit(db, user.id, "patient.profile_updated", "user", user.id, request)
    db.commit()
    return patient_profile(user)


@app.get("/api/consents")
def list_consents(user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.ConsentRecord).where(m.ConsentRecord.patient_id == user.id).order_by(m.ConsentRecord.recorded_at.desc())).all()
    latest = {}
    for row in rows:
        latest.setdefault(row.purpose_code, row)
    return [{"id": r.id, "purpose_code": r.purpose_code, "status": r.status,
             "notice_version": r.notice_version, "recorded_at": to_iso(r.recorded_at)} for r in latest.values()]


@app.post("/api/consents", status_code=201)
def set_consent(payload: ConsentIn, request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    db.add(m.ConsentRecord(patient_id=user.id, notice_version="demo-v1", purpose_code=payload.purpose_code,
                           status=payload.status, actor_id=user.id))
    audit(db, user.id, "consent.changed", "consent", user.id, request, meta={"purpose": payload.purpose_code, "status": payload.status})
    db.commit()
    return {"purpose_code": payload.purpose_code, "status": payload.status}


@app.get("/api/appointments")
def list_appointments(user: m.User = Depends(current_user), db: Session = Depends(get_db)):
    query = select(m.Appointment)
    if user.role == "patient":
        query = query.where(m.Appointment.patient_id == user.id)
    elif user.role not in {"receptionist", "doctor"}:
        raise HTTPException(403, "You do not have access to appointments")
    appointments = db.scalars(query).all()
    appointments.sort(key=lambda a: normalize_dt(a.starts_at), reverse=True)
    return [appointment_out(a, db) for a in appointments[:200]]


def create_appointment(payload: AppointmentIn, patient_id: str, actor: m.User, request: Request, db: Session):
    start, end = normalize_dt(payload.starts_at), normalize_dt(payload.ends_at)
    if end <= start or (end - start) > timedelta(hours=3) or start < now_utc() - timedelta(minutes=2):
        raise HTTPException(422, "Choose a valid future appointment time")
    provider = db.get(m.User, payload.provider_id) if payload.provider_id else None
    if payload.provider_id and (not provider or provider.role != "doctor"):
        raise HTTPException(422, "Choose a valid doctor")
    query = select(m.Appointment).where(m.Appointment.status == "scheduled")
    if payload.provider_id:
        query = query.where(m.Appointment.provider_id == payload.provider_id)
    for existing in db.scalars(query):
        if normalize_dt(existing.starts_at) < end and normalize_dt(existing.ends_at) > start:
            raise HTTPException(409, "That time slot is already booked")
    appointment = m.Appointment(patient_id=patient_id, provider_id=payload.provider_id, starts_at=start, ends_at=end,
                                reason_minimised=payload.reason_minimised.strip() if payload.reason_minimised else None)
    db.add(appointment)
    db.flush()
    audit(db, actor.id, "appointment.created", "appointment", appointment.id, request)
    db.commit()
    return appointment_out(appointment, db)


@app.post("/api/appointments", status_code=201)
def book_appointment(payload: AppointmentIn, request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    return create_appointment(payload, user.id, user, request, db)


@app.post("/api/staff/appointments", status_code=201)
def staff_book_appointment(payload: AppointmentIn, patient_id: str, request: Request,
                           user: m.User = Depends(require_roles("receptionist")), db: Session = Depends(get_db)):
    patient = db.get(m.User, patient_id)
    if not patient or patient.role != "patient":
        raise HTTPException(404, "Patient not found")
    return create_appointment(payload, patient.id, user, request, db)


@app.patch("/api/appointments/{appointment_id}/cancel")
def cancel_appointment(appointment_id: str, request: Request, user: m.User = Depends(current_user), db: Session = Depends(get_db)):
    appointment = db.get(m.Appointment, appointment_id)
    if not appointment or (user.role == "patient" and appointment.patient_id != user.id):
        raise HTTPException(404, "Appointment not found")
    if user.role not in {"patient", "receptionist"}:
        raise HTTPException(403, "You do not have access to cancel appointments")
    appointment.status = "cancelled"
    audit(db, user.id, "appointment.cancelled", "appointment", appointment.id, request)
    db.commit()
    return appointment_out(appointment, db)


@app.get("/api/patients")
def list_patients(user: m.User = Depends(require_roles("receptionist", "doctor", "privacy_officer")), db: Session = Depends(get_db)):
    people = db.scalars(select(m.User).where(m.User.role == "patient", m.User.is_active.is_(True)).limit(200)).all()
    people.sort(key=lambda person: person.display_name.casefold())
    return [{"id": p.id, "display_name": p.display_name,
             "contact_value": mask_contact_value(p.contact_value) if user.role == "receptionist" else None} for p in people]


@app.get("/api/records/mine")
def my_records(request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    notes = db.scalars(select(m.ClinicalNote).where(m.ClinicalNote.patient_id == user.id,
                            m.ClinicalNote.visibility_status == "released").order_by(m.ClinicalNote.record_date.desc())).all()
    rx = db.scalars(select(m.Prescription).where(m.Prescription.patient_id == user.id,
                          m.Prescription.visibility_status == "released").order_by(m.Prescription.issue_date.desc())).all()
    audit(db, user.id, "records.patient_view", "patient_record", user.id, request)
    db.commit()
    return {"notes": [{"id": n.id, "record_date": to_iso(n.record_date), "note_text": n.note_text} for n in notes],
            "prescriptions": [{"id": p.id, "issue_date": to_iso(p.issue_date), "instructions": p.instructions} for p in rx]}


@app.get("/api/staff/patients/{patient_id}/records")
def staff_patient_records(patient_id: str, request: Request, user: m.User = Depends(require_roles("doctor")), db: Session = Depends(get_db)):
    patient = db.get(m.User, patient_id)
    if not patient or patient.role != "patient":
        raise HTTPException(404, "Patient not found")
    notes = db.scalars(select(m.ClinicalNote).where(m.ClinicalNote.patient_id == patient_id).order_by(m.ClinicalNote.record_date.desc())).all()
    rx = db.scalars(select(m.Prescription).where(m.Prescription.patient_id == patient_id).order_by(m.Prescription.issue_date.desc())).all()
    audit(db, user.id, "records.staff_view", "patient_record", patient_id, request)
    db.commit()
    return {"notes": [{"id": n.id, "record_date": to_iso(n.record_date), "note_text": n.note_text, "visibility_status": n.visibility_status} for n in notes],
            "prescriptions": [{"id": p.id, "issue_date": to_iso(p.issue_date), "instructions": p.instructions, "visibility_status": p.visibility_status} for p in rx]}


@app.post("/api/staff/clinical-notes", status_code=201)
def create_note(payload: ClinicalNoteIn, request: Request, user: m.User = Depends(require_roles("doctor")), db: Session = Depends(get_db)):
    patient = db.get(m.User, payload.patient_id)
    if not patient or patient.role != "patient":
        raise HTTPException(404, "Patient not found")
    note = m.ClinicalNote(patient_id=patient.id, doctor_id=user.id, note_text=payload.note_text,
                          visibility_status=payload.visibility_status)
    db.add(note); db.flush(); audit(db, user.id, "record.note_created", "clinical_note", note.id, request)
    db.commit()
    return {"id": note.id, "visibility_status": note.visibility_status}


@app.post("/api/staff/prescriptions", status_code=201)
def create_prescription(payload: PrescriptionIn, request: Request, user: m.User = Depends(require_roles("doctor")), db: Session = Depends(get_db)):
    patient = db.get(m.User, payload.patient_id)
    if not patient or patient.role != "patient":
        raise HTTPException(404, "Patient not found")
    rx = m.Prescription(patient_id=patient.id, doctor_id=user.id, instructions=payload.instructions,
                        visibility_status=payload.visibility_status)
    db.add(rx); db.flush(); audit(db, user.id, "record.prescription_created", "prescription", rx.id, request)
    db.commit()
    return {"id": rx.id, "visibility_status": rx.visibility_status}


@app.post("/api/rights-requests", status_code=201)
def submit_rights_request(payload: RequestIn, request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    row = m.RightsRequest(patient_id=user.id, request_type=payload.request_type, description=payload.description)
    db.add(row); db.flush(); audit(db, user.id, "rights_request.submitted", "rights_request", row.id, request)
    db.commit()
    return request_out(row, patient_view=True)


@app.get("/api/rights-requests/mine")
def my_rights_requests(user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.RightsRequest).where(m.RightsRequest.patient_id == user.id).order_by(m.RightsRequest.submitted_at.desc())).all()
    return [request_out(r, patient_view=True) for r in rows]


@app.post("/api/erasure-receipt")
def check_erasure_receipt(payload: ErasureReceiptLookupIn, db: Session = Depends(get_db)):
    row = db.get(m.RightsRequest, payload.request_id)
    if not row or row.request_type != "full_erasure" or not hmac.compare_digest(payload.receipt_token, erasure_receipt_token(row)):
        raise HTTPException(404, "Receipt not found. Check the request reference and receipt code.")
    receipt_expires_at = normalize_dt(row.completed_at) + timedelta(days=30) if row.completed_at else None
    if receipt_expires_at and receipt_expires_at < now_utc():
        raise HTTPException(410, "This receipt has expired. Contact the clinic using its published contact method.")
    actions = db.scalars(select(m.ErasureAction).where(m.ErasureAction.request_id == row.id)).all()
    removed = sorted({a.entity_type.replace("_", " ") for a in actions if a.action in {"deleted", "deactivated_and_scrubbed"}})
    return {"status": row.status, "decision": row.decision, "completed_at": to_iso(row.completed_at),
            "receipt_expires_at": to_iso(receipt_expires_at), "follow_up_due_at": to_iso(row.follow_up_due_at),
            "pending_erasure_categories": json.loads(row.pending_erasure_categories or "[]"),
            "removed_categories": removed}


@app.get("/api/staff/rights-requests")
def staff_rights_requests(user: m.User = Depends(require_roles("privacy_officer", "security_admin")), db: Session = Depends(get_db)):
    # Full-profile erasure requests go directly to the security admin; the privacy officer queue excludes them.
    request_filter = m.RightsRequest.request_type == "full_erasure" if user.role == "security_admin" else m.RightsRequest.request_type != "full_erasure"
    rows = db.scalars(select(m.RightsRequest).where(request_filter).order_by(m.RightsRequest.submitted_at.desc()).limit(200)).all()
    output = []
    for row in rows:
        patient = db.get(m.User, row.patient_id)
        output.append({**request_out(row, staff_view=True),
                       "patient_name": patient.display_name if patient else "Erased patient",
                       "patient_erased": not patient or not patient.is_active})
    return output


@app.get("/api/staff/rights-requests/{request_id}/erasure-summary")
def erasure_summary(request_id: str, user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    row = db.get(m.RightsRequest, request_id)
    if not row or row.request_type != "full_erasure":
        raise HTTPException(404, "Full erasure request not found")
    patient_id = row.patient_id
    counts = {
        "profile": 1 if db.get(m.User, patient_id) and db.get(m.User, patient_id).is_active else 0,
        "appointments": db.scalar(select(func.count()).select_from(m.Appointment).where(m.Appointment.patient_id == patient_id)) or 0,
        "consent_records": db.scalar(select(func.count()).select_from(m.ConsentRecord).where(m.ConsentRecord.patient_id == patient_id)) or 0,
        "clinical_notes": db.scalar(select(func.count()).select_from(m.ClinicalNote).where(m.ClinicalNote.patient_id == patient_id)) or 0,
        "prescriptions": db.scalar(select(func.count()).select_from(m.Prescription).where(m.Prescription.patient_id == patient_id)) or 0,
        "complaints": db.scalar(select(func.count()).select_from(m.PatientComplaint).where(m.PatientComplaint.patient_id == patient_id)) or 0,
        "audit_events": db.scalar(select(func.count()).select_from(m.AuditEvent).where(or_(m.AuditEvent.actor_id == patient_id, (m.AuditEvent.entity_type == "patient") & (m.AuditEvent.entity_id == patient_id)))) or 0,
        "request_history": db.scalar(select(func.count()).select_from(m.RightsRequest).where(m.RightsRequest.patient_id == patient_id, m.RightsRequest.id != row.id)) or 0,
    }
    return {"categories": counts, "note": "Counts cover this app's database only; backups, external systems, and legally retained records require separate review."}


@app.get("/api/staff/rights-requests/{request_id}/cancelled-appointments")
def erasure_appointments(request_id: str, user: m.User = Depends(require_roles("privacy_officer")), db: Session = Depends(get_db)):
    row = db.get(m.RightsRequest, request_id)
    if not row or row.request_type != "erasure":
        raise HTTPException(404, "Erasure request not found")
    appointments = db.scalars(select(m.Appointment).where(
        m.Appointment.patient_id == row.patient_id,
        m.Appointment.status == "cancelled"
    )).all()
    appointments.sort(key=lambda a: normalize_dt(a.starts_at), reverse=True)
    return [{"id": a.id, "starts_at": to_iso(a.starts_at), "ends_at": to_iso(a.ends_at),
             "status": a.status} for a in appointments]


@app.patch("/api/staff/rights-requests/{request_id}")
def review_rights_request(request_id: str, payload: ReviewIn, request: Request,
                          user: m.User = Depends(require_roles("privacy_officer", "security_admin")), db: Session = Depends(get_db)):
    row = db.get(m.RightsRequest, request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if row.request_type == "full_erasure" and user.role != "security_admin":
        raise HTTPException(403, "Only the security admin can review or execute a full patient-data erasure")
    if row.request_type != "full_erasure" and user.role != "privacy_officer":
        raise HTTPException(403, "Only the privacy officer can review this request type")
    if payload.status in {"under_review", "partially_approved", "declined"} and not (payload.decision or "").strip():
        raise HTTPException(422, "A patient-visible reason is required for this status")
    row.status, row.reviewer_id = payload.status, user.id
    row.decision = payload.decision.strip() if payload.decision else None
    row.legal_basis_note = payload.legal_basis_note
    if payload.status == "partially_approved":
        allowed_categories = {"profile", "appointments", "consent_records", "clinical_notes", "prescriptions", "complaints", "audit_events", "request_history"}
        if row.request_type != "full_erasure":
            raise HTTPException(400, "Partial category review is available for full erasure requests")
        if len(payload.erase_categories) != len(set(payload.erase_categories)) or not set(payload.erase_categories) <= allowed_categories:
            raise HTTPException(400, "Choose valid data categories once each")
        if not payload.erase_categories:
            raise HTTPException(400, "Select the categories that need a second review")
        row.pending_erasure_categories = json.dumps(payload.erase_categories, separators=(",", ":"))
        row.follow_up_due_at = now_utc() + timedelta(days=3)
        row.completed_at = None
    elif payload.status in {"approved", "declined", "resolved"}:
        row.pending_erasure_categories = None
        row.follow_up_due_at = None
    if payload.status == "resolved":
        row.completed_at = now_utc()
    if (payload.erase_categories or payload.confirm_erasure) and payload.status != "partially_approved":
        if row.request_type != "full_erasure":
            raise HTTPException(400, "All-data deletion requires a full erasure request")
        if not payload.confirm_erasure:
            raise HTTPException(400, "Confirm the all-data erasure action")
        if payload.appointment_ids:
            raise HTTPException(400, "Use category selection for a full erasure request")
        if payload.status not in {"approved", "resolved"}:
            raise HTTPException(400, "Approve the full erasure request before deleting data")
        if not payload.legal_basis_note or not payload.legal_basis_note.strip():
            raise HTTPException(400, "Record the retention review before deleting data")
        allowed_categories = {"profile", "appointments", "consent_records", "clinical_notes", "prescriptions", "complaints", "audit_events", "request_history"}
        if len(payload.erase_categories) != len(set(payload.erase_categories)) or not set(payload.erase_categories) <= allowed_categories:
            raise HTTPException(400, "Choose valid data categories once each")
        patient = db.get(m.User, row.patient_id)
        if not patient or patient.role != "patient":
            raise HTTPException(404, "Patient profile not found")
        if "profile" in payload.erase_categories and not patient.is_active:
            raise HTTPException(409, "This patient profile has already been deactivated")
        category_models = {
            "appointments": m.Appointment,
            "consent_records": m.ConsentRecord,
            "clinical_notes": m.ClinicalNote,
            "prescriptions": m.Prescription,
            "complaints": m.PatientComplaint,
        }
        for category in payload.erase_categories:
            if category == "profile":
                continue
            if category == "audit_events":
                records = db.scalars(select(m.AuditEvent).where(or_(m.AuditEvent.actor_id == patient.id, (m.AuditEvent.entity_type == "patient") & (m.AuditEvent.entity_id == patient.id)))).all()
            elif category == "request_history":
                records = db.scalars(select(m.RightsRequest).where(m.RightsRequest.patient_id == patient.id, m.RightsRequest.id != row.id)).all()
                for prior in records:
                    actions = db.scalars(select(m.ErasureAction).where(m.ErasureAction.request_id == prior.id)).all()
                    for action_row in actions:
                        db.delete(action_row)
            else:
                model = category_models[category]
                records = db.scalars(select(model).where(model.patient_id == patient.id)).all()
            if category == "complaints":
                complaint_ids = [record.id for record in records]
                if complaint_ids:
                    updates = db.scalars(select(m.ComplaintUpdate).where(m.ComplaintUpdate.complaint_id.in_(complaint_ids))).all()
                    for update in updates:
                        db.delete(update)
            for record in records:
                db.add(m.ErasureAction(request_id=row.id, entity_type=category, entity_id=record.id,
                                       action="deleted", reason=payload.legal_basis_note.strip(), executed_by=user.id))
                db.delete(record)
        if "profile" in payload.erase_categories:
            # Remove login identifiers and invalidate sessions while retaining a non-login tombstone
            # for records that the clinic has separately documented it must retain.
            patient.username = "erased-" + patient.id
            patient.display_name = "Erased patient"
            patient.contact_value = None
            patient.password_hash = hash_password(secrets.token_urlsafe(32))
            patient.is_active = False
            sessions = db.scalars(select(m.LoginSession).where(m.LoginSession.user_id == patient.id)).all()
            for session in sessions:
                db.delete(session)
            requests = db.scalars(select(m.RightsRequest).where(m.RightsRequest.patient_id == patient.id)).all()
            for prior_request in requests:
                prior_request.description = None
            events = db.scalars(select(m.AuditEvent).where(or_(m.AuditEvent.actor_id == patient.id, (m.AuditEvent.entity_type == "patient") & (m.AuditEvent.entity_id == patient.id)))).all()
            for event_row in events:
                event_row.actor_id = None
                if event_row.entity_type == "patient" and event_row.entity_id == patient.id:
                    event_row.entity_id = None
                event_row.reason = None
                event_row.request_id = None
                event_row.metadata_minimised = None
            db.add(m.ErasureAction(request_id=row.id, entity_type="profile", entity_id=patient.id,
                                   action="deactivated_and_scrubbed", reason=payload.legal_basis_note.strip(), executed_by=user.id))
        row.status = "resolved"
        row.completed_at = now_utc()
        row.pending_erasure_categories = None
        row.follow_up_due_at = None
        audit(db, user.id, "rights_request.full_erasure_executed", "rights_request", row.id, request,
              reason="Approved categories: " + ", ".join(payload.erase_categories))
    if payload.appointment_ids:
        if row.request_type != "erasure" or payload.status not in {"approved", "resolved"}:
            raise HTTPException(400, "Appointment erasure requires an approved erasure request")
        if not payload.legal_basis_note:
            raise HTTPException(400, "Record the retention review before deleting appointments")
        if len(payload.appointment_ids) != len(set(payload.appointment_ids)):
            raise HTTPException(400, "Choose each cancelled appointment only once")
        appointments = db.scalars(select(m.Appointment).where(
            m.Appointment.id.in_(payload.appointment_ids),
            m.Appointment.patient_id == row.patient_id,
            m.Appointment.status == "cancelled"
        )).all()
        if len(appointments) != len(payload.appointment_ids):
            raise HTTPException(400, "Only this patient's cancelled appointments can be erased")
        for appointment in appointments:
            db.add(m.ErasureAction(request_id=row.id, entity_type="appointment", entity_id=appointment.id,
                                   action="deleted", reason="Reviewer-approved category deletion", executed_by=user.id))
            db.delete(appointment)
    audit(db, user.id, "rights_request.reviewed", "rights_request", row.id, request,
          reason=payload.legal_basis_note or payload.decision)
    db.commit()
    return request_out(row)


@app.post("/api/complaints", status_code=201)
def submit_complaint(payload: ComplaintIn, request: Request, user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    complaint = m.PatientComplaint(patient_id=user.id, category=payload.category, description=payload.description)
    db.add(complaint); db.flush()
    audit(db, user.id, "complaint.submitted", "complaint", complaint.id, request)
    db.commit()
    return complaint_out(complaint, db, patient_view=True)


@app.get("/api/complaints/mine")
def my_complaints(user: m.User = Depends(require_roles("patient")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.PatientComplaint).where(m.PatientComplaint.patient_id == user.id).order_by(m.PatientComplaint.submitted_at.desc())).all()
    return [complaint_out(c, db, patient_view=True) for c in rows]


@app.get("/api/staff/complaints")
def staff_complaints(user: m.User = Depends(require_roles("privacy_officer")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.PatientComplaint).order_by(m.PatientComplaint.submitted_at.desc()).limit(200)).all()
    return [complaint_out(c, db, patient_view=False) for c in rows]


@app.post("/api/staff/complaints/{complaint_id}/updates", status_code=201)
def add_complaint_update(complaint_id: str, payload: ComplaintUpdateIn, request: Request,
                         user: m.User = Depends(require_roles("privacy_officer")), db: Session = Depends(get_db)):
    complaint = db.get(m.PatientComplaint, complaint_id)
    if not complaint:
        raise HTTPException(404, "Complaint not found")
    update = m.ComplaintUpdate(complaint_id=complaint.id, author_id=user.id,
                               visibility=payload.visibility, message=payload.message)
    if payload.status:
        allowed = {"submitted", "acknowledged", "under_review", "awaiting_patient", "action_in_progress", "resolved", "closed"}
        if payload.status not in allowed:
            raise HTTPException(422, "Invalid complaint status")
        complaint.status = payload.status
        if payload.status in {"resolved", "closed"}:
            complaint.resolved_at = now_utc()
            if payload.visibility == "patient":
                complaint.resolution_summary = payload.message
    complaint.assigned_officer = user.id
    db.add(update); audit(db, user.id, "complaint.updated", "complaint", complaint.id, request,
               meta={"visibility": payload.visibility, "status": payload.status})
    db.commit()
    return complaint_out(complaint, db, patient_view=False)


@app.get("/api/admin/incidents")
def list_incidents(user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.SecurityIncident).order_by(m.SecurityIncident.detected_at.desc()).limit(200)).all()
    return [incident_out(i, db) for i in rows]


@app.post("/api/admin/incidents", status_code=201)
def create_incident(payload: IncidentIn, request: Request,
                    user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    incident = m.SecurityIncident(summary=payload.summary, severity=payload.severity, source=payload.source,
                                   affected_categories=json.dumps(payload.affected_categories), assigned_to=user.id)
    db.add(incident); db.flush()
    db.add(m.IncidentAction(incident_id=incident.id, actor_id=user.id, action="created", note="Incident opened for triage"))
    audit(db, user.id, "incident.created", "incident", incident.id, request)
    db.commit()
    return incident_out(incident, db)


@app.post("/api/admin/incidents/demo-simulate", status_code=201)
def simulate_incident(request: Request, user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    incident = m.SecurityIncident(summary="Synthetic demo: unusual access pattern detected; no real data was exposed.",
                                   severity="medium", source="demo simulation", affected_categories='["appointments"]',
                                   assigned_to=user.id)
    db.add(incident); db.flush()
    db.add(m.IncidentAction(incident_id=incident.id, actor_id=user.id, action="created", note="Synthetic alert created for the hackathon demo"))
    audit(db, user.id, "incident.demo_simulated", "incident", incident.id, request)
    db.commit()
    return incident_out(incident, db)


@app.post("/api/admin/incidents/{incident_id}/actions", status_code=201)
def incident_action(incident_id: str, payload: IncidentActionIn, request: Request,
                    user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    incident = db.get(m.SecurityIncident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    allowed_statuses = {"detected", "triage", "containing", "investigating", "notification_review", "recovering", "closed", "false_positive", "duplicate"}
    if payload.status and payload.status not in allowed_statuses:
        raise HTTPException(422, "Invalid incident status")
    if payload.status:
        incident.status = payload.status
    if payload.action == "containment":
        incident.containment = payload.note
    elif payload.action == "impact_assessment":
        incident.impact_assessment = payload.note
    elif payload.action == "closure" and payload.status == "closed":
        incident.closure_summary = payload.note
    if payload.action == "notification_review":
        db.add(m.IncidentNotification(incident_id=incident.id, recipient_type="review pending",
                                      reviewed_by=user.id, decision=payload.status or "reviewed"))
    db.add(m.IncidentAction(incident_id=incident.id, actor_id=user.id, action=payload.action, note=payload.note))
    audit(db, user.id, "incident.action", "incident", incident.id, request, reason=payload.action)
    db.commit()
    return incident_out(incident, db)


@app.get("/api/admin/audit-events")
def list_audit_events(limit: int = 100, user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    safe_limit = min(max(limit, 1), 250)
    rows = db.scalars(select(m.AuditEvent).order_by(m.AuditEvent.occurred_at.desc()).limit(safe_limit)).all()
    return [{"id": a.id, "actor_id": a.actor_id, "action": a.action, "entity_type": a.entity_type,
             "entity_id": a.entity_id, "occurred_at": to_iso(a.occurred_at), "outcome": a.outcome,
             "reason": a.reason, "request_id": a.request_id} for a in rows]


@app.get("/api/admin/patient-register")
def patient_register(response: Response, user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    """Live index of active patients with category totals; details are fetched on demand."""
    active = db.scalars(select(m.User).where(m.User.role == "patient", m.User.is_active.is_(True))).all()
    active.sort(key=lambda patient: patient.display_name.casefold())
    rows = []
    for patient in active:
        rows.append({
            "id": patient.id, "display_name": patient.display_name,
            "masked_contact": mask_contact_value(patient.contact_value),
            "records": {
                "appointments": db.scalar(select(func.count()).select_from(m.Appointment).where(m.Appointment.patient_id == patient.id)) or 0,
                "consent_records": db.scalar(select(func.count()).select_from(m.ConsentRecord).where(m.ConsentRecord.patient_id == patient.id)) or 0,
                "clinical_notes": db.scalar(select(func.count()).select_from(m.ClinicalNote).where(m.ClinicalNote.patient_id == patient.id)) or 0,
                "prescriptions": db.scalar(select(func.count()).select_from(m.Prescription).where(m.Prescription.patient_id == patient.id)) or 0,
                "rights_requests": db.scalar(select(func.count()).select_from(m.RightsRequest).where(m.RightsRequest.patient_id == patient.id)) or 0,
                "complaints": db.scalar(select(func.count()).select_from(m.PatientComplaint).where(m.PatientComplaint.patient_id == patient.id)) or 0,
            },
        })
    inactive = db.scalar(select(func.count()).select_from(m.User).where(
        m.User.role == "patient", m.User.is_active.is_(False))) or 0
    response.headers["Cache-Control"] = "no-store"
    return {"active_patient_count": len(active), "inactive_erased_profiles": inactive,
            "refreshed_at": to_iso(now_utc()), "patients": rows,
            "note": "Count is active patient profiles. Inactive erased profiles may remain as minimal tombstones; backups and external systems are not included."}


@app.get("/api/admin/patient-register/{patient_id}")
def patient_register_detail(patient_id: str, request: Request, response: Response,
                            user: m.User = Depends(require_roles("security_admin")), db: Session = Depends(get_db)):
    patient = db.get(m.User, patient_id)
    if not patient or patient.role != "patient" or not patient.is_active:
        raise HTTPException(404, "Active patient not found")

    def staff_name(staff_id):
        staff = db.get(m.User, staff_id) if staff_id else None
        return staff.display_name if staff else None

    appointments = db.scalars(select(m.Appointment).where(m.Appointment.patient_id == patient_id)).all()
    consents = db.scalars(select(m.ConsentRecord).where(m.ConsentRecord.patient_id == patient_id)).all()
    notes = db.scalars(select(m.ClinicalNote).where(m.ClinicalNote.patient_id == patient_id)).all()
    prescriptions = db.scalars(select(m.Prescription).where(m.Prescription.patient_id == patient_id)).all()
    rights = db.scalars(select(m.RightsRequest).where(m.RightsRequest.patient_id == patient_id)).all()
    complaints = db.scalars(select(m.PatientComplaint).where(m.PatientComplaint.patient_id == patient_id)).all()
    right_ids = [item.id for item in rights]
    complaint_ids = [item.id for item in complaints]
    actions = db.scalars(select(m.ErasureAction).where(m.ErasureAction.request_id.in_(right_ids))).all() if right_ids else []
    updates = db.scalars(select(m.ComplaintUpdate).where(m.ComplaintUpdate.complaint_id.in_(complaint_ids))).all() if complaint_ids else []
    events = db.scalars(select(m.AuditEvent).where(or_(m.AuditEvent.actor_id == patient_id, (m.AuditEvent.entity_type == "patient") & (m.AuditEvent.entity_id == patient_id))).order_by(m.AuditEvent.occurred_at.desc())).all()
    response.headers["Cache-Control"] = "no-store"
    audit(db, user.id, "admin.patient_record_viewed", "patient", patient_id, request)
    db.commit()
    return {
        "profile": {"id": patient.id, "username": patient.username, "display_name": patient.display_name,
                    "contact_value": patient.contact_value, "created_at": to_iso(patient.created_at),
                    "last_login_at": to_iso(patient.last_login_at), "active": patient.is_active},
        "appointments": [{"id": x.id, "provider": staff_name(x.provider_id), "starts_at": to_iso(x.starts_at),
                          "ends_at": to_iso(x.ends_at), "status": x.status, "reason": x.reason_minimised,
                          "created_at": to_iso(x.created_at)} for x in appointments],
        "consent_records": [{"notice_version": x.notice_version, "purpose": x.purpose_code, "status": x.status,
                             "recorded_at": to_iso(x.recorded_at)} for x in consents],
        "clinical_notes": [{"doctor": staff_name(x.doctor_id), "record_date": to_iso(x.record_date),
                            "visibility": x.visibility_status, "retention_class": x.retention_class, "text": x.note_text} for x in notes],
        "prescriptions": [{"doctor": staff_name(x.doctor_id), "issue_date": to_iso(x.issue_date),
                           "visibility": x.visibility_status, "retention_class": x.retention_class,
                           "instructions": x.instructions} for x in prescriptions],
        "rights_requests": [{"type": x.request_type, "description": x.description, "status": x.status,
                             "submitted_at": to_iso(x.submitted_at), "decision": x.decision,
                             "retention_note": x.legal_basis_note, "completed_at": to_iso(x.completed_at)} for x in rights],
        "complaints": [{"category": x.category, "description": x.description, "status": x.status,
                        "priority": x.priority, "submitted_at": to_iso(x.submitted_at), "resolution": x.resolution_summary,
                        "updates": [{"message": u.message, "visibility": u.visibility, "created_at": to_iso(u.created_at)}
                                    for u in updates if u.complaint_id == x.id]} for x in complaints],
        "erasure_actions": [{"category": x.entity_type, "action": x.action, "reason": x.reason,
                             "executed_at": to_iso(x.executed_at), "executed_by": staff_name(x.executed_by)} for x in actions],
        "audit_events": [{"action": x.action, "entity_type": x.entity_type, "occurred_at": to_iso(x.occurred_at),
                          "outcome": x.outcome, "reason": x.reason} for x in events],
        "excluded": ["password hashes", "session tokens", "database credentials"],
    }

@app.get("/api/admin/retention-policies")
def list_retention(user: m.User = Depends(require_roles("security_admin", "privacy_officer")), db: Session = Depends(get_db)):
    rows = db.scalars(select(m.RetentionPolicy).order_by(m.RetentionPolicy.data_category)).all()
    return [{"id": p.id, "data_category": p.data_category, "rule_description": p.rule_description,
             "retention_trigger": p.retention_trigger, "duration_days": p.duration_days,
             "legal_reference": p.legal_reference, "verified": p.verified,
             "reviewed_at": to_iso(p.reviewed_at)} for p in rows]

from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

@app.get("/{full_path:path}", include_in_schema=False)
def serve_frontend(full_path: str):
    if full_path.startswith("api/") or full_path in {"docs", "redoc", "openapi.json"}:
        raise HTTPException(404, "Not found")
    root = FRONTEND_DIST.resolve()
    candidate = (root / full_path).resolve()
    if root in candidate.parents and candidate.is_file():
        return FileResponse(candidate)
    index = root / "index.html"
    if index.is_file():
        return FileResponse(index)
    raise HTTPException(404, "Frontend bundle not built. Run npm run build in frontend/.")
