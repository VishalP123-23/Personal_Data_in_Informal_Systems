from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.models import User, ComplaintUpdate, RightsRequest
from app.db import get_db
from .conftest import TestingSession, sign_in


def test_patient_cannot_read_another_patients_clinical_records(client):
    sign_in(client, "patient.a")
    db = TestingSession()
    other = db.scalar(select(User).where(User.username == "patient.b"))
    response = client.get(f"/api/staff/patients/{other.id}/records")
    assert response.status_code == 403
    db.close()


def test_patient_erasure_request_requires_privacy_review(client):
    patient = sign_in(client, "patient.a")
    created = client.post("/api/rights-requests", json={"request_type":"erasure", "description":"Please review my appointment data."})
    assert created.status_code == 201
    request_id = created.json()["id"]
    privacy = sign_in(client, "privacy")
    response = client.patch(f"/api/staff/rights-requests/{request_id}", json={
        "status":"under_review", "decision":"We are reviewing the request.",
        "legal_basis_note":"Retention assessment required; no period assumed.", "delete_appointments":False
    })
    assert response.status_code == 200
    sign_in(client, "patient.a")
    assert client.get("/api/rights-requests/mine").json()[0]["status"] == "under_review"
    db = TestingSession()
    row = db.get(RightsRequest, request_id)
    assert row.reviewer_id is not None
    db.close()


def test_internal_complaint_notes_never_return_to_patient(client):
    sign_in(client, "patient.a")
    created = client.post("/api/complaints", json={"category":"consent_concern", "description":"I have a question about an optional choice."})
    assert created.status_code == 201
    complaint_id = created.json()["id"]
    sign_in(client, "privacy")
    response = client.post(f"/api/staff/complaints/{complaint_id}/updates", json={
        "message":"Internal triage note for the privacy team.", "visibility":"internal", "status":"under_review"
    })
    assert response.status_code == 201
    sign_in(client, "patient.a")
    patient_view = client.get("/api/complaints/mine").json()[0]
    assert patient_view["updates"] == []
    db = TestingSession()
    update = db.scalar(select(ComplaintUpdate).where(ComplaintUpdate.complaint_id == complaint_id))
    assert update.visibility == "internal"
    db.close()


def test_optional_consent_is_separate_and_withdrawable(client):
    sign_in(client, "patient.a")
    granted = client.post("/api/consents", json={"purpose_code":"optional_reminders", "status":"granted"})
    assert granted.status_code == 201
    withdrawn = client.post("/api/consents", json={"purpose_code":"optional_reminders", "status":"withdrawn"})
    assert withdrawn.status_code == 201
    history = client.get("/api/consents").json()
    assert history[0]["status"] == "withdrawn"


def test_security_admin_only_can_create_incident(client):
    sign_in(client, "patient.a")
    denied = client.post("/api/admin/incidents/demo-simulate")
    assert denied.status_code == 403
    sign_in(client, "security")
    allowed = client.post("/api/admin/incidents/demo-simulate")
    assert allowed.status_code == 201
    assert "Synthetic demo" in allowed.json()["summary"]


def test_appointment_conflict_for_same_provider_is_rejected(client):
    db = TestingSession()
    doctor = db.scalar(select(User).where(User.username == "doctor"))
    provider_id = doctor.id
    db.close()
    sign_in(client, "patient.a")
    start = datetime.now(timezone.utc) + timedelta(days=4)
    start = start.replace(minute=0, second=0, microsecond=0)
    payload = {"starts_at":start.isoformat(), "ends_at":(start+timedelta(minutes=30)).isoformat(), "provider_id":provider_id}
    assert client.post("/api/appointments", json=payload).status_code == 201
    sign_in(client, "patient.b")
    conflict = client.post("/api/appointments", json=payload)
    assert conflict.status_code == 409


def test_internal_resolution_is_not_exposed(client):
    sign_in(client, "patient.a")
    row = client.post("/api/complaints", json={"category":"other", "description":"Synthetic privacy concern"}).json()
    sign_in(client, "privacy")
    assert client.post(f"/api/staff/complaints/{row['id']}/updates", json={"message":"Confidential internal resolution", "visibility":"internal", "status":"closed"}).status_code == 201
    sign_in(client, "patient.a")
    result = client.get("/api/complaints/mine").json()[0]
    assert result["resolution_summary"] is None
    assert result["updates"] == []


def test_csrf_missing_is_rejected(client):
    sign_in(client, "patient.a")
    del client.headers["X-CSRF-Token"]
    assert client.post("/api/consents", json={"purpose_code":"optional_reminders", "status":"granted"}).status_code == 403
