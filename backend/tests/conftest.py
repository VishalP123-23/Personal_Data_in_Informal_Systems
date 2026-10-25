import os
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-for-local-suite"
os.environ["PERSONAL_DATA_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app
from app.models import User
from app.security import hash_password

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSession()
    password = hash_password("DemoPassword#2026")
    db.add_all([
        User(username="patient.a", password_hash=password, role="patient", display_name="A Demo"),
        User(username="patient.b", password_hash=password, role="patient", display_name="B Demo"),
        User(username="privacy", password_hash=password, role="privacy_officer", display_name="Privacy Demo"),
        User(username="security", password_hash=password, role="security_admin", display_name="Security Demo"),
        User(username="doctor", password_hash=password, role="doctor", display_name="Doctor Demo"),
    ])
    db.commit(); db.close()
    def override_get_db():
        session = TestingSession()
        try: yield session
        finally: session.close()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def sign_in(client, username):
    response = client.post("/api/auth/login", json={"username": username, "password": "DemoPassword#2026"})
    assert response.status_code == 200, response.text
    client.headers.update({"X-CSRF-Token": client.cookies.get("clinic_csrf")})
    return response.json()
