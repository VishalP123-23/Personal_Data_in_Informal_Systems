import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base
from app.models import User, Appointment
from app.file_mirror import install_mirror
from app.data_protection import decrypt_personal_data


def test_file_tracks_committed_creation_cancellation_and_erasure(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "test.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    output = tmp_path / "appointments.json"
    install_mirror(factory, engine, output)
    with factory() as db:
        patient = User(username="mirror.patient", password_hash="test", role="patient", display_name="Mirror Demo")
        db.add(patient)
        db.flush()
        start = datetime.now(timezone.utc) + timedelta(days=2)
        appointment = Appointment(patient_id=patient.id, starts_at=start, ends_at=start+timedelta(minutes=30))
        db.add(appointment)
        db.commit()
        saved = json.loads(output.read_text())
        assert saved["count"] == 1
        assert saved["encrypted_appointments"].startswith("enc:v1:")
        assert json.loads(decrypt_personal_data(saved["encrypted_appointments"], "export.appointments"))[0]["id"] == appointment.id
        appointment.status = "cancelled"
        db.commit()
        cancelled = json.loads(output.read_text())
        assert json.loads(decrypt_personal_data(cancelled["encrypted_appointments"], "export.appointments"))[0]["status"] == "cancelled"
        db.delete(appointment)
        db.rollback()
        assert json.loads(output.read_text())["count"] == 1
        db.delete(appointment)
        db.commit()
        erased = json.loads(output.read_text())
        assert erased["count"] == 0
        assert json.loads(decrypt_personal_data(erased["encrypted_appointments"], "export.appointments")) == []
    engine.dispose()
