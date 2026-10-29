"""Local desktop OAuth and read-only Gmail API connector.

OAuth tokens and fetched message bodies are kept in memory only. The app asks
for Gmail read-only access and never sends, deletes, or changes Gmail messages.
"""
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS_FILE = ROOT / "credentials.json"
REDIRECT_URI = "http://127.0.0.1:8000"
SCOPES = "openid email https://www.googleapis.com/auth/gmail.readonly"
GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"

_lock = threading.RLock()
_pending = {}
_tokens = None
_profile_email = None
_messages = {}
_email_analyzer = None


def set_email_analyzer(analyzer):
    global _email_analyzer
    _email_analyzer = analyzer


def _credentials():
    if not CREDENTIALS_FILE.is_file():
        raise RuntimeError("Google sign-in is not configured yet. Add your downloaded Google OAuth credentials as credentials.json in the PhishGuard folder, then restart the app.")
    try:
        data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        client = data.get("installed") or data.get("web") or data
        client_id = client["client_id"]
        client_secret = client.get("client_secret", "")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("credentials.json is invalid. Download a Desktop app OAuth JSON file from Google Cloud and save it in the PhishGuard folder.") from exc
    return client_id, client_secret


def configured():
    return CREDENTIALS_FILE.is_file()


def create_authorization_url():
    client_id, _ = _credentials()
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with _lock:
        _pending[state] = (verifier, time.time() + 600)
    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    return GOOGLE_AUTH + "?" + urllib.parse.urlencode(params)


def _http_json(url, *, data=None, headers=None, timeout=25):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        detail = ""
        if hasattr(exc, "read"):
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error_description", "")
            except Exception:
                pass
        raise RuntimeError(detail or f"Google request failed: {exc}") from exc


def finish_authorization(code, state):
    global _tokens, _profile_email, _messages
    with _lock:
        pending = _pending.pop(state, None)
    if not pending or pending[1] < time.time():
        raise RuntimeError("Google sign-in expired or the security state did not match. Please try again.")
    client_id, client_secret = _credentials()
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": pending[0],
    }
    tokens = _http_json(TOKEN_ENDPOINT, data=token_data)
    if not tokens.get("access_token"):
        raise RuntimeError("Google did not return an access token. Please try signing in again.")
    with _lock:
        _tokens = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "expires_at": time.time() + int(tokens.get("expires_in", 3600)) - 60,
        }
        _profile_email = None
        _messages = {}
    profile = _http_json(GMAIL_API + "/profile", headers={"Authorization": f"Bearer {_tokens['access_token']}"})
    with _lock:
        _profile_email = profile.get("emailAddress", "Google account")
    return _profile_email


def _access_token():
    global _tokens
    with _lock:
        if not _tokens:
            raise RuntimeError("Sign in with Google to view your Gmail inbox.")
        if _tokens["expires_at"] > time.time():
            return _tokens["access_token"]
        refresh_token = _tokens.get("refresh_token")
        if not refresh_token:
            _tokens = None
            raise RuntimeError("Your Google session expired. Sign in again to reconnect Gmail.")
        client_id, client_secret = _credentials()
        refreshed = _http_json(TOKEN_ENDPOINT, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        })
        _tokens["access_token"] = refreshed["access_token"]
        _tokens["expires_at"] = time.time() + int(refreshed.get("expires_in", 3600)) - 60
        return _tokens["access_token"]


def status():
    with _lock:
        return {"connected": bool(_tokens), "email": _profile_email, "configured": configured()}


def sign_out():
    global _tokens, _profile_email, _messages
    with _lock:
        _tokens = None
        _profile_email = None
        _messages = {}


def _api_get(path, query=None):
    url = GMAIL_API + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return _http_json(url, headers={"Authorization": f"Bearer {_access_token()}"})


def _decode_body(payload):
    chunks = []
    def walk(part):
        mime = part.get("mimeType", "")
        body = part.get("body", {}).get("data")
        if body and mime == "text/plain":
            try:
                raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
                chunks.append(raw.decode("utf-8", errors="replace"))
            except Exception:
                pass
        for child in part.get("parts", []) or []:
            walk(child)
    walk(payload or {})
    return "\n".join(chunks).strip()


def list_messages(limit=30):
    global _messages
    ids = _api_get("/messages", {"labelIds": "INBOX", "maxResults": min(max(int(limit), 1), 50)}).get("messages", [])
    fresh = {}
    items = []
    for ref in ids:
        message = _api_get("/messages/" + urllib.parse.quote(ref["id"], safe=""), {"format": "full"})
        headers = {h.get("name", "").lower(): h.get("value", "") for h in message.get("payload", {}).get("headers", [])}
        body = _decode_body(message.get("payload", {})) or message.get("snippet", "")
        try:
            received = parsedate_to_datetime(headers.get("date", "")).isoformat()
        except Exception:
            try:
                received = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(int(message.get("internalDate", 0)) / 1000))
            except Exception:
                received = ""
        sender = headers.get("from", "Unknown sender")
        subject = headers.get("subject", "(no subject)")
        if _email_analyzer is None:
            raise RuntimeError("Email analyzer is not initialized")
        score, level, verdict, evidence, recommendations = _email_analyzer({"sender": sender, "subject": subject, "body": body})
        item = {
            "id": message["id"],
            "kind": "email",
            "title": subject,
            "detail": message.get("snippet", ""),
            "actor": sender,
            "created": received,
            "score": score,
            "level": level,
            "verdict": verdict,
            "evidence": evidence,
            "recommendations": recommendations,
            "status": "Open",
            "gmail": True,
        }
        fresh[message["id"]] = {**item, "body": body}
        items.append(item)
    with _lock:
        _messages = fresh
    return items


def get_message(message_id):
    with _lock:
        item = _messages.get(message_id)
    if not item:
        raise RuntimeError("This message is no longer in the current inbox cache. Refresh Gmail and try again.")
    return item


