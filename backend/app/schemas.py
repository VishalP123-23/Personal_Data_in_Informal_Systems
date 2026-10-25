from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re

class LoginIn(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=128)

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    contact_value: str | None = Field(default=None, max_length=120)
    notice_acknowledged: bool

    @field_validator("username")
    @classmethod
    def username_is_not_government_id(cls, value):
        if re.fullmatch(r"\d{12}", value):
            raise ValueError("Choose a username; do not use Aadhaar or government ID numbers")
        return value

    @field_validator("contact_value")
    @classmethod
    def contact_must_be_email_or_phone(cls, value):
        return validate_contact_value(value)


def validate_contact_value(value):
    if value is None or not value.strip():
        return None
    value = value.strip()
    digits = re.sub(r"\D", "", value)
    if "@" not in value and len(digits) == 12 and not value.startswith("+"):
        raise ValueError("Do not enter Aadhaar or government ID numbers here")
    if "@" in value:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address")
    elif not (7 <= len(digits) <= 15) or not re.fullmatch(r"[+()\d .-]+", value):
        raise ValueError("Enter a phone number or email address only")
    return value


class ProfileUpdateIn(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    contact_value: str | None = Field(default=None, max_length=120)

    @field_validator("contact_value")
    @classmethod
    def contact_must_be_email_or_phone(cls, value):
        return validate_contact_value(value)

class ConsentIn(BaseModel):
    purpose_code: str = Field(pattern=r"^optional_reminders$")
    status: str = Field(pattern=r"^(granted|withdrawn)$")

class AppointmentIn(BaseModel):
    starts_at: datetime
    ends_at: datetime
    reason_minimised: str | None = Field(default=None, max_length=160)
    provider_id: str | None = None

class RequestIn(BaseModel):
    request_type: str = Field(pattern=r"^(access|correction|erasure|full_erasure)$")
    description: str | None = Field(default=None, max_length=1200)

class ErasureReceiptLookupIn(BaseModel):
    request_id: str = Field(min_length=36, max_length=36)
    receipt_token: str = Field(min_length=72, max_length=72, pattern=r"^hmac:v1:[a-f0-9]{64}$")

class ReviewIn(BaseModel):
    status: str = Field(pattern=r"^(under_review|approved|partially_approved|declined|resolved)$")
    decision: str | None = Field(default=None, min_length=3, max_length=1200)
    legal_basis_note: str | None = Field(default=None, max_length=1200)
    appointment_ids: list[str] = Field(default_factory=list, max_length=100)
    erase_categories: list[str] = Field(default_factory=list, max_length=10)
    confirm_erasure: bool = False

class ComplaintIn(BaseModel):
    category: str = Field(min_length=3, max_length=50)
    description: str = Field(min_length=5, max_length=2000)

class ComplaintUpdateIn(BaseModel):
    message: str = Field(min_length=1, max_length=1600)
    visibility: str = Field(pattern=r"^(patient|internal)$")
    status: str | None = Field(default=None, max_length=30)

class IncidentIn(BaseModel):
    summary: str = Field(min_length=5, max_length=1200)
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    source: str = Field(default="administrator report", max_length=100)
    affected_categories: list[str] = Field(default_factory=list, max_length=20)

class IncidentActionIn(BaseModel):
    action: str = Field(min_length=3, max_length=40)
    note: str = Field(min_length=3, max_length=1200)
    status: str | None = Field(default=None, max_length=30)

class ClinicalNoteIn(BaseModel):
    patient_id: str
    note_text: str = Field(min_length=3, max_length=5000)
    visibility_status: str = Field(default="draft", pattern=r"^(draft|released)$")

class PrescriptionIn(BaseModel):
    patient_id: str
    instructions: str = Field(min_length=3, max_length=2000)
    visibility_status: str = Field(default="draft", pattern=r"^(draft|released)$")
