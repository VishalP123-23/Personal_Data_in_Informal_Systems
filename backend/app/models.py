from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
from .data_protection import EncryptedDateTime, EncryptedText, personal_data_hash

def uid() -> str:
    return str(uuid4())

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(EncryptedText("user.username"), unique=True)
    username_digest: Mapped[str | None] = mapped_column(String(72), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), index=True)
    display_name: Mapped[str] = mapped_column(EncryptedText("user.display_name"))
    display_name_digest: Mapped[str | None] = mapped_column(String(72), nullable=True)
    contact_value: Mapped[str | None] = mapped_column(EncryptedText("user.contact_value"), nullable=True)
    contact_digest: Mapped[str | None] = mapped_column(String(72), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class PrivacyNotice(Base):
    __tablename__ = "privacy_notices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    version: Mapped[str] = mapped_column(String(30), unique=True)
    language: Mapped[str] = mapped_column(String(20), default="en")
    notice_text: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ConsentRecord(Base):
    __tablename__ = "consent_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    notice_version: Mapped[str] = mapped_column(String(30))
    purpose_code: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))

class Appointment(Base):
    __tablename__ = "appointments"
    __table_args__ = (Index("ix_appt_provider_start", "provider_id", "starts_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    starts_at: Mapped[datetime] = mapped_column(EncryptedDateTime("appointment.starts_at"))
    ends_at: Mapped[datetime] = mapped_column(EncryptedDateTime("appointment.ends_at"))
    status: Mapped[str] = mapped_column(String(20), default="scheduled")
    reason_minimised: Mapped[str | None] = mapped_column(EncryptedText("appointment.reason_minimised"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(EncryptedDateTime("appointment.created_at"), default=utcnow)

class ClinicalNote(Base):
    __tablename__ = "clinical_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    doctor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    note_text: Mapped[str] = mapped_column(EncryptedText("clinical_note.note_text"))
    record_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    visibility_status: Mapped[str] = mapped_column(String(20), default="draft")
    retention_class: Mapped[str] = mapped_column(String(30), default="review_required")

class Prescription(Base):
    __tablename__ = "prescriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    doctor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    instructions: Mapped[str] = mapped_column(EncryptedText("prescription.instructions"))
    issue_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    visibility_status: Mapped[str] = mapped_column(String(20), default="draft")
    retention_class: Mapped[str] = mapped_column(String(30), default="review_required")

class RightsRequest(Base):
    __tablename__ = "rights_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    request_type: Mapped[str] = mapped_column(String(30))
    description: Mapped[str | None] = mapped_column(EncryptedText("rights_request.description"), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="submitted", index=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decision: Mapped[str | None] = mapped_column(EncryptedText("rights_request.decision"), nullable=True)
    legal_basis_note: Mapped[str | None] = mapped_column(EncryptedText("rights_request.legal_basis_note"), nullable=True)
    pending_erasure_categories: Mapped[str | None] = mapped_column(Text, nullable=True)
    follow_up_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class ErasureAction(Base):
    __tablename__ = "erasure_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str] = mapped_column(ForeignKey("rights_requests.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    entity_id: Mapped[str] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(EncryptedText("erasure_action.reason"))
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_by: Mapped[str] = mapped_column(ForeignKey("users.id"))

class SecurityIncident(Base):
    __tablename__ = "security_incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="detected", index=True)
    source: Mapped[str] = mapped_column(EncryptedText("security_incident.source"))
    affected_categories: Mapped[str] = mapped_column(EncryptedText("security_incident.affected_categories"))
    summary: Mapped[str] = mapped_column(EncryptedText("security_incident.summary"))
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    containment: Mapped[str | None] = mapped_column(EncryptedText("security_incident.containment"), nullable=True)
    impact_assessment: Mapped[str | None] = mapped_column(EncryptedText("security_incident.impact_assessment"), nullable=True)
    closure_summary: Mapped[str | None] = mapped_column(EncryptedText("security_incident.closure_summary"), nullable=True)

class IncidentAction(Base):
    __tablename__ = "incident_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("security_incidents.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(EncryptedText("incident_action.action"))
    note: Mapped[str] = mapped_column(EncryptedText("incident_action.note"))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class IncidentNotification(Base):
    __tablename__ = "incident_notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("security_incidents.id", ondelete="CASCADE"), index=True)
    recipient_type: Mapped[str] = mapped_column(String(40))
    reviewed_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str] = mapped_column(String(30))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    method: Mapped[str | None] = mapped_column(EncryptedText("incident_notification.method"), nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(EncryptedText("incident_notification.evidence_ref"), nullable=True)

class PatientComplaint(Base):
    __tablename__ = "patient_complaints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    patient_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(EncryptedText("patient_complaint.category"))
    description: Mapped[str] = mapped_column(EncryptedText("patient_complaint.description"))
    status: Mapped[str] = mapped_column(String(30), default="submitted", index=True)
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    assigned_officer: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_summary: Mapped[str | None] = mapped_column(EncryptedText("patient_complaint.resolution_summary"), nullable=True)

class ComplaintUpdate(Base):
    __tablename__ = "complaint_updates"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    complaint_id: Mapped[str] = mapped_column(ForeignKey("patient_complaints.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    visibility: Mapped[str] = mapped_column(String(20), default="patient")
    message: Mapped[str] = mapped_column(EncryptedText("complaint_update.message"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    outcome: Mapped[str] = mapped_column(String(30), default="success")
    reason: Mapped[str | None] = mapped_column(EncryptedText("audit_event.reason"), nullable=True)
    request_id: Mapped[str | None] = mapped_column(EncryptedText("audit_event.request_id"), nullable=True)
    metadata_minimised: Mapped[str | None] = mapped_column(EncryptedText("audit_event.metadata_minimised"), nullable=True)

class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    data_category: Mapped[str] = mapped_column(String(60), unique=True)
    rule_description: Mapped[str] = mapped_column(Text)
    retention_trigger: Mapped[str] = mapped_column(String(160))
    duration_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    legal_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


@event.listens_for(User, "before_insert")
@event.listens_for(User, "before_update")
def update_user_digests(mapper, connection, target):
    target.username_digest = personal_data_hash(target.username, "user.username")
    target.display_name_digest = personal_data_hash(target.display_name, "user.display_name")
    target.contact_digest = personal_data_hash(target.contact_value, "user.contact_value")
