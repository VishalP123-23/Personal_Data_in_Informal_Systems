# CCTV footage handling concept

**Status:** design only. The prototype has no camera connection, video upload, or video storage. Do not use the prototype to collect real CCTV footage.

## Data and purpose

Identifiable CCTV video is personal data. A recording may contain patients, staff, visitors, and other bystanders, so a clip is not automatically data about only one patient.

Before processing footage, the clinic should document the specific purpose (for example, a defined premises-security or incident-investigation purpose), the applicable lawful basis, which cameras and areas are in scope, who is responsible, and the retention schedule. Do not treat a general “under surveillance” sign as consent by itself. Use the sign as a notice. If consent is the chosen basis, obtain and record separate clear affirmative action; confirm that it is freely given and can be withdrawn. If another lawful basis or a legal requirement applies, record and verify it instead.

## Proposed data flow

1. The building camera/NVR remains the recording source and keeps its ordinary rolling footage under a separately approved schedule.
2. The app does not copy or index every recording. An authorised privacy or security officer imports only a short, case-related excerpt when a documented need and lawful basis are established.
3. Store the video as an encrypted file in a restricted media store, separate from PostgreSQL. Use authenticated encryption, protect encryption keys separately from the media and database, and encrypt transfer from the NVR/import workstation.
4. PostgreSQL stores only a random clip reference and minimum metadata: case/request reference, camera/location code, capture interval, purpose and lawful-basis record, uploader, access history, retention expiry/review date, deletion state, and an optional patient link only where necessary for the case.
5. A keyed or cryptographic digest may verify that a clip has not changed; it does not replace encryption and does not make the footage anonymous.
6. Playback is limited to authorised reviewers. Record each view, export, redaction, and deletion. Do not expose raw clips through the patient portal by default. Review clips for bystanders and redact or limit disclosure where appropriate.
7. At expiry, delete the app’s encrypted copy and handle NVR loop retention, backups, legal holds, and deletion evidence under the approved schedule. Do not invent a universal retention period in code.

## Notice at the building

The notice should be easy to see before a person enters the covered area. It should say that CCTV is operating, state the specific purpose, identify who operates it, provide a privacy contact and a way to exercise rights or complain, and direct people to the fuller privacy notice. The clinic must set the retention period or explain the criteria after legal review. A sign communicates notice; it does not, on its own, establish the clear affirmative action required when processing relies on consent.

The clinic should review camera placement and angles to avoid areas where people have a strong expectation of privacy. Audio recording and facial recognition are out of scope and should remain off unless separately assessed and authorised.

## Controls required before implementation

- Confirm the camera/NVR make, model, export/API method, and where its recordings currently live.
- Confirm the documented purpose and lawful basis, including whether another healthcare or premises-security rule applies.
- Approve the notice, retention/deletion schedule, access roles, backup handling, and request workflow.
- Decide who can import clips, review them, redact bystanders, and authorise disclosure or erasure.
- Implement encrypted file storage, separate key management, access logging, size/type limits, and deletion/backup expiry before enabling any real footage.

## DPDP reference points

The Act defines personal data broadly as data about an individual identifiable by or in relation to that data. Sections 4–6 address lawful purpose, notice, and consent; consent requires a clear affirmative action. Rule 3 specifies notice content. Rule 6 lists encryption and access controls among minimum security safeguards. Section 8(7) and Rule 8 address erasure subject to continuing purpose and legal retention. The relevant phased provisions are scheduled to commence on 13 May 2027 under the published commencement notifications; this concept is designed ahead of that date and does not itself establish legal compliance.

- [Digital Personal Data Protection Act, 2023 (official text)](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf)
- [Digital Personal Data Protection Rules, 2025 (official Gazette)](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf)
- [Act commencement notification, G.S.R. 843(E)](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf)
