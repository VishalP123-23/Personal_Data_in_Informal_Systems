# Personal Data in Informal Systems

**Clinic / Patient — local-first healthcare privacy web application**

A runnable hackathon prototype for a small clinic and its patients. Patients use a browser portal; clinic staff use role-specific browser workspaces. The frontend and API run locally, and the database is a local PostgreSQL instance. No third-party messaging, cloud storage, hosted authentication, analytics, remote OCR, or runtime asset services are integrated.

> **Demo only.** Use synthetic data. This project is not a medical tool, legal opinion, security certification, or production-ready system. Have qualified legal and security reviewers verify retention periods, notices, incident duties, and deployment controls before real use.

## Start on this computer

Double-click **Start Demo.cmd** in this folder, then open http://127.0.0.1:8001. Keep the terminal open while using the website. Choose a demo role on the sign-in page, then click Sign in.

This installation uses a project-owned PostgreSQL database in `work/pgdata` on loopback port **55432**, with credentials in `backend/.env`. It does not change your existing PostgreSQL database. The instructions below also describe a fresh installation; do not overwrite the configured `.env` on this machine.

## What is included

- Patient self-registration, local sign-in, profile, appointments, released notes/prescriptions, optional reminder choice, rights requests, and privacy complaints.
- Receptionist patient directory and appointment scheduling with overlap checks.
- Doctor workspace for synthetic clinical notes and prescriptions, with draft/released visibility.
- Privacy officer queues for access/correction/erasure requests, complaint updates, and retention review.
- Security administrator incident workflow, synthetic breach simulation, notification review, and audit trail.
- PostgreSQL schema and Alembic migration, encrypted personal-data fields with keyed lookup digests, repeatable synthetic demo seed, role-ownership tests, and responsive React/TypeScript UI.
- Local loopback-only defaults. Development UI uses 127.0.0.1:5173; API uses 127.0.0.1:8001. A built frontend can be served by FastAPI on port 8001.

## Demo accounts

All accounts below are fictional, local-only demo accounts. Change or remove them before any shared deployment.

| Role | Username | Password |
|---|---|---|
| Patient | demo.patient | PatientDemo#2026 |
| Reception desk | demo.reception | ReceptionDemo#2026 |
| Doctor | demo.doctor | DoctorDemo#2026 |
| Privacy officer | demo.privacy | PrivacyDemo#2026 |
| Security admin | demo.security | SecurityDemo#2026 |

The seeded patient includes a synthetic appointment, note, and prescription. Prescription content is demonstration text, not medical advice.

## Prerequisites

- Windows 10/11, PowerShell, Python 3.11 or newer, Node.js LTS with npm, and PostgreSQL 15 or newer.
- Docker Desktop is optional and only used to run a local PostgreSQL container. No hosted or paid services are required.

### 1. Prepare the local database

Start your local PostgreSQL service, then open psql as a local PostgreSQL administrator and run:

~~~sql
CREATE USER clinic_app WITH PASSWORD 'choose-a-local-password';
CREATE DATABASE clinic_privacy OWNER clinic_app;
~~~

If clinic_app or clinic_privacy already exists, keep your existing local values and update backend/.env accordingly. Do not commit passwords.

Optional local PostgreSQL container:

~~~powershell
docker compose up -d db
~~~

The container binds only to 127.0.0.1:5432 and stores its data in a local Docker volume. To stop it: docker compose down.

### 2. Configure and start the API

From this project folder:

~~~powershell
Copy-Item backend/.env.example backend/.env
~~~

Edit backend/.env: set DATABASE_URL to your local PostgreSQL username/password, generate a random SECRET_KEY, and keep COOKIE_SECURE=false for loopback-only HTTP development. The application reads this file at startup. The .env file is ignored by Git.

Doctor accounts use the same local username-and-password demo sign-in as the other seeded roles. All accounts are fictional demo accounts, not suitable for real clinic data.

Then generate a separate local personal-data encryption key and add it to `backend/.env` as `PERSONAL_DATA_KEY`: use a cryptographically random 32-byte key encoded with URL-safe Base64. Keep that key outside database backups and never commit it. Losing the key makes encrypted fields and the JSON snapshot unreadable; keep a protected recovery copy. Install backend dependencies before starting the app so the migration can encrypt existing rows.

Then:

~~~powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
alembic upgrade head
python -m app.seed_demo
uvicorn app.main:app --host 127.0.0.1 --port 8001
~~~

Keep this terminal open. API health endpoint: http://127.0.0.1:8001/api/health.

### 3. Start the website in development mode

Open a second PowerShell terminal at the project folder:

~~~powershell
cd frontend
npm install
npm run dev
~~~

Open http://127.0.0.1:5173. The Vite development server proxies /api to the local FastAPI service.

### Production-like local preview

Build the frontend and serve it from the same local FastAPI process:

~~~powershell
cd frontend
npm run build
cd ..\backend
uvicorn app.main:app --host 127.0.0.1 --port 8001
~~~

Then open http://127.0.0.1:8001. This is still a development/hackathon setup, not a hardened production deployment.

## Live patient register

Sign in as the **Security admin** and open **Patient register** to see the active patient count and select a patient to view the data categories stored for that account. The page refreshes the count every three seconds. The readable view is role-protected and access is recorded in the audit trail.

In VS Code, open data/patient_count.json for an automatically refreshed aggregate count and category totals. It contains no names or patient-level details. The existing data/appointments.json and PostgreSQL files are not readable patient directories; sensitive details remain encrypted at rest. The patient register shows the fields and records the app actually holds, not records in backups or external systems. A deactivated profile may remain as a minimal tombstone when some data is retained for a reviewed reason.
## Tests and checks

From backend/, with the virtual environment active:

~~~powershell
pytest
~~~

From frontend/:

~~~powershell
npm run build
npm test
~~~

The API test suite uses an isolated in-memory SQLite database and synthetic accounts. The actual app uses PostgreSQL by default.

## Local data and privacy boundaries

- No real patient data. Avoid real names, contact information, credentials, or records in screenshots and demos.
- No WhatsApp, Telegram, SMS gateway, email provider, cloud storage, analytics, remote AI/OCR, external database, or hosted identity provider.
- The only network listeners default to loopback; do not expose Vite, Uvicorn, or PostgreSQL to the public internet.
- Patient sign-in uses local username/password accounts with Argon2id password hashes and server-side sessions. The demo login is password-only and has no production identity proofing or password reset service.
- Cookie-authenticated writes use a CSRF token. Development cookies are not Secure because loopback HTTP is used; use HTTPS and COOKIE_SECURE=true for any LAN test, and configure TLS/firewall rules before doing so.
- Audit events minimize metadata but are append-only only at the application layer; a database administrator can still alter them.
- Backups are not automatically configured. Document, encrypt, restrict, expire, and test any backups before real deployment. The UI does not promise instant deletion from backups.
- Incident alerts are workflow signals, not automatic breach determinations. The notification workflow is a manual checklist; no external notices are sent.
- Data retention categories are deliberately unverified placeholders. Patients can submit a full-data erasure request; only the security admin can review and execute selected in-app categories after recording a retention assessment and explicit confirmation. Profile deletion disables the demo account and scrubs its login/contact identifiers. The workflow does not cover backups, external systems, application logs, or data not represented in this app; some records may require retention. This is a demonstrator, not a complete erasure guarantee.
- CCTV footage is not ingested or stored by the prototype. The future handling concept, DPDP notice/consent distinction, encrypted storage, access controls, and retention requirements are documented in [docs/cctv-data-handling-concept.md](docs/cctv-data-handling-concept.md).

## Architecture

~~~text
Patient browser / clinic browser
            | same-origin local HTTP in loopback demo
            v
React + TypeScript + Vite UI -- development proxy --> FastAPI
                                                    |
                                                    v
                                           Local PostgreSQL
~~~

The browser never connects directly to PostgreSQL. All authorization is enforced in FastAPI; hiding a UI control is not treated as access control. Roles are patient, receptionist, doctor, privacy officer, and security administrator.

## Legal and product limits

The retention register is not a legal schedule. The project intentionally avoids hard-coded blanket retention claims and automatic erasure of all clinic records. The DPDP Act/Rules have phased commencement and other healthcare, tax, consumer, and professional requirements may apply. Verify current law and clinic-specific duties independently. Never claim that this prototype makes a clinic DPDP-compliant.
