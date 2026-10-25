# Architecture and threat model

## Boundary

The prototype has one clinic-controlled API, one local PostgreSQL database, and first-party patient/staff browser screens. External messaging and storage APIs are intentionally absent. A browser on the same machine reaches the loopback application. A LAN deployment would additionally depend on the clinic network and HTTPS configuration; it is not enabled by default.

## Roles

- Patient: own profile, own appointments, released records, optional reminder preference, rights requests, and complaints.
- Receptionist: basic patient directory and scheduling; no clinical notes or privacy complaint decisions.
- Doctor: patient records and synthetic notes/prescriptions; no security administration.
- Privacy officer: rights requests, complaint investigation, and retention review.
- Security administrator: incident and audit views.

The API applies role and ownership checks on every protected operation. Staff UI menus are not security controls.

The security administrator has a patient register that reports active profiles and opens linked app records on demand. Sensitive details are returned only by an authenticated, audited endpoint and are not copied to a plaintext file. A generated VS Code JSON file contains aggregate counts only; it refreshes after database commits. Active patient count excludes inactive erased-profile tombstones.

## Threats addressed in the demo

- Cross-patient object access through guessed IDs: UUIDs, ownership checks, role-scoped endpoints, and tests.
- Password disclosure: Argon2id password hashes; generic failed-login message; basic process-local rate limit.
- Cross-site request forgery: SameSite=Strict cookies and a CSRF cookie/header check for authenticated writes.
- Accidental over-collection: minimal profile fields and reminders as a separate optional choice.
- Internal misuse: role separation and audit events for sensitive actions.
- Erasure requests: patient full-data requests go directly to the security-admin queue. The admin can delete selected in-app categories after recording a retention assessment and confirming the action; profile deletion deactivates and scrubs the account identifiers. Backups and external systems are outside the demo workflow.

## Limitations

This is a hackathon prototype. The login rate limiter is process-local, session revocation is per-session, audit is not cryptographically immutable, no real identity verification exists, no production monitoring/backup/key-management system is configured, and the incident workflow is manually driven. No real clinical use is supported.
