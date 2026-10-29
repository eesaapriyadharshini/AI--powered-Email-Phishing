# PhishGuard

A local Gmail-style cybersecurity application for phishing email triage, suspicious login assessment, QR image checks, and incident tracking. Users can connect a real Gmail account through Google's OAuth consent screen or open the sample demo inbox.

## Run on Windows

1. Configure Google OAuth once using the steps below if you want to read real Gmail. The sample inbox works without setup.
2. Double-click `run.bat` or start it from a terminal in this folder.
3. Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Choose **Continue with Google** for your own Gmail or **Use the sample demo inbox** for sample messages.
4. Stop the server with **Ctrl+C** in its terminal.

The launcher supports Python 3.10+ and tries the Python 3.13 launcher on Windows.

## Connect a real Gmail account

1. In Google Cloud Console, create a project and enable the **Gmail API**.
2. Set up the Google Auth Platform consent screen. For local testing, set the audience to **Testing** and add the Google account you will use under **Test users**.
3. Create an OAuth client with application type **Desktop app**, then download its JSON credentials file.
4. Rename the downloaded file to `credentials.json` and place it beside `run.bat` in the PhishGuard folder.
5. Restart `run.bat`, open the site in Chrome or Edge, and click **Continue with Google**. Google will handle sign-in and consent on its official page.

The app requests only `gmail.readonly`. It lists up to 30 recent inbox messages and analyzes their text locally with the included explainable phishing rules. It never sends, deletes, labels, or modifies Gmail messages. The OAuth access token and fetched message bodies are held in server memory and are cleared when the app stops; sign in again after restarting. Keep `credentials.json` private and do not commit it.

Google treats `gmail.readonly` as a restricted scope. Testing accounts may need to be listed as test users, and public distribution can require Google's OAuth verification.

The SQLite database is created in `data/phishguard.sqlite3` and stores local demo and investigation records. Gmail message bodies and OAuth tokens are not stored in that database.

## Features

- Gmail-style inbox with sample data or authorized read-only Gmail messages.
- Email analysis using explainable rules for urgency, credential requests, payment lures, sender mismatch, and suspicious URLs.
- Login event scoring based on failed attempts, new devices, unusual locations, and outcome; assess one event or import a CSV.
- QR image upload and QR decoding in a supporting browser, with payload inspection that never opens the destination. Invalid, unreadable, risky, and unsupported payloads are recorded for investigation.
- Risk levels, evidence, response recommendations, incident status, and analyst action notes.
- Local demo data and an API suitable for wiring up authorized connectors.

CSV login import accepts these column headers (case-insensitive):

```text
user,country,device,outcome,failed_attempts,new_device,new_location
student@campus.example,India,Windows laptop,success,0,true,false
```

## API

The service exposes a small versioned JSON API, including:

- `GET /api/v1/auth/status`, `GET /api/v1/gmail/messages`, and `GET /api/v1/gmail/messages/{id}`
- `GET /api/v1/events` and `GET /api/v1/dashboard/summary`
- `POST /api/v1/analyze/email`
- `POST /api/v1/analyze/login` and `POST /api/v1/logins/import`
- `POST /api/v1/analyze/qr`
- `GET /api/v1/events/{id}`
- `POST /api/v1/incidents/{id}/status` and `/actions`

## Important integration boundary

This deliverable runs as a **local demonstration application**. The email and login analyzers use transparent heuristics; they are not trained ML models and cannot establish that a message or login is safe. QR image decoding uses the browser's `BarcodeDetector` API, available in current Chromium browsers. When decoding is unavailable or fails, the application records a review alert instead of opening or executing content.

Live campus audit-log ingestion, external URL reputation lookups, and external response actions are not configured. Gmail access requires the account owner's OAuth consent and Google Cloud credentials. The app binds only to `127.0.0.1`; it is not hardened for deployment on a network. Response recommendations are for review; the app does not quarantine mail, block URLs, revoke sessions, or reset passwords.
