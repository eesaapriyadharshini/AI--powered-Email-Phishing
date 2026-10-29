from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from contextlib import contextmanager
import json, sqlite3, re, uuid, datetime, urllib.parse, webbrowser
import google_mail

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "phishguard.sqlite3"
STATIC = ROOT / "frontend"
DB.parent.mkdir(parents=True, exist_ok=True)

@contextmanager
def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def init():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, kind TEXT, title TEXT, detail TEXT, actor TEXT, created TEXT, score INTEGER, level TEXT, verdict TEXT, evidence TEXT, recommendations TEXT, status TEXT DEFAULT 'Open');
        CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, event_id TEXT, action TEXT, note TEXT, created TEXT);
        ''')
        if db.execute("SELECT count(*) FROM events").fetchone()[0] == 0:
            samples = [
                ("email","Urgent password verification","Your account will be disabled today. Verify your password at http://campus-security-login.example/verify","student@campus.example",82,"High","Likely phishing",["Urgent credential request","HTTP URL uses a lookalike security domain","Account threat pressure in message"],["Report and quarantine the message","Do not open the link; verify through the official campus portal"]),
                ("login","Successful login from new region","Successful sign-in from an unseen device and distant region","student@campus.example",71,"High","Suspicious login",["New device for this account","Location differs from recent baseline","Successful authentication after repeated failures"],["Verify with the account owner","Revoke sessions and reset password if unrecognized"]),
                ("email","Campus library weekly update","Your reserved books are ready for pickup this week.","library@campus.example",8,"Low","Likely benign",["No risky link or credential request detected"],["No action required"]),
                ("qr","QR poster sample","https://example.org/campus-events","security@campus.example",18,"Low","No obvious threat detected",["Decoded HTTPS URL","No obvious obfuscation detected"],["Verify the destination before opening"]),
            ]
            for kind,title,detail,actor,score,level,verdict,evidence,recs in samples:
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,'Open')",(str(uuid.uuid4()),kind,title,detail,actor,datetime.datetime.now(datetime.timezone.utc).isoformat(),score,level,verdict,json.dumps(evidence),json.dumps(recs)))
        # Keep the Gmail-style demo inbox populated even when an older local
        # database already exists. Add only missing built-in sample messages.
        inbox_samples = [
            ("Campus IT Security", "URGENT: Campus Email Password Expiration Notice", "Your university single-sign-on password will expire within 2 hours. Verify your credentials at http://campus-portal-verification.login-auth.org/verify", "it-support@campus-service-alert.com", 82, "High", "Likely phishing", ["Urgent credential request", "Sender domain is not the official campus domain", "Suspicious login portal link"], ["Report and quarantine the message", "Do not open the link; use the official campus portal"]),
            ("Bursar Student Financial Services", "Immediate Notice: Unclaimed Tuition Refund $480.00", "You have an uncollected student fee refund of $480.00. Confirm your identity at http://student-refund-portal.web-financial-services.com/claim", "bursar-refunds@campus-billing-desk.org", 76, "High", "Likely phishing", ["Unexpected refund offer", "Requests identity confirmation", "Financial lookalike URL"], ["Do not enter financial details", "Verify through the official bursar website"]),
            ("University Library", "Library Book Due Date Reminder: Operating Systems", "Your borrowed book 'Modern Operating Systems (4th Ed)' is due in 3 days. Visit https://library.campus.edu to renew.", "circulation@library.campus.edu", 8, "Low", "Likely benign", ["No risky link or credential request detected"], ["No action required"]),
            ("Campus Registrar", "Course Registration Window for Next Semester", "Your registration appointment begins this Monday at 08:00 AM. Review your degree audit at https://registrar.campus.edu/registration.", "registrar@campus.edu", 12, "Low", "Likely benign", ["Campus sender and HTTPS campus link"], ["Review your registration in the official campus portal"]),
        ]
        for sender_name, title, detail, actor, score, level, verdict, evidence, recs in inbox_samples:
            if not db.execute("SELECT 1 FROM events WHERE kind='email' AND title=? LIMIT 1", (title,)).fetchone():
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,'Open')", (str(uuid.uuid4()), "email", title, detail, sender_name, datetime.datetime.now(datetime.timezone.utc).isoformat(), score, level, verdict, json.dumps(evidence), json.dumps(recs)))

def classify_url(url):
    findings=[]
    parsed=urllib.parse.urlparse(url)
    host=(parsed.hostname or "").lower()
    if parsed.scheme not in ("https",): findings.append("Destination does not use HTTPS")
    if any(x in host for x in ("login", "verify", "secure", "account", "password")) and not host.endswith(("google.com","microsoft.com","campus.example")):
        findings.append("Destination uses a credential-themed hostname")
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b",host): findings.append("Destination uses a raw IP address")
    if "@" in url: findings.append("URL contains an @ sign that can disguise its destination")
    if len(url)>180: findings.append("Unusually long destination URL")
    if host.count("-")>=3: findings.append("Hostname contains several hyphens")
    return findings

def analyze_email(data):
    subject=str(data.get("subject","")); body=str(data.get("body","")); sender=str(data.get("sender","")); text=(subject+" "+body).lower()
    evidence=[]; score=8
    cues=[("urgent|immediately|within 24 hours|today", "Urgency or deadline language",18), ("password|verify your account|sign in|login", "Credential or account access request",20), ("gift card|wire transfer|payment|bank details", "Payment or financial request",22), ("suspended|disabled|locked|terminate", "Threat of account restriction",14), ("unusual activity|confirm your identity", "Identity confirmation request",12)]
    for pattern,label,points in cues:
        if re.search(pattern,text): evidence.append(label); score+=points
    urls=re.findall(r"https?://[^\s<>\"']+",body,re.I)
    for url in urls:
        flags=classify_url(url)
        evidence.extend([f"Link: {x}" for x in flags]); score+=min(24,10*len(flags))
    domain=sender.rsplit("@",1)[-1].lower()
    if any(word in domain for word in ("gmail.com","outlook.com","yahoo.com")) and any(word in text for word in ("campus","university","student")):
        evidence.append("Free email sender claims a campus identity"); score+=12
    if not evidence: evidence=["No strong phishing indicators found by the rules-based demo analyzer"]
    score=min(score,100); level="Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=35 else "Low"
    verdict="Likely phishing" if score>=60 else "Needs review" if score>=35 else "Likely benign"
    return score,level,verdict,evidence,["Report and quarantine the message" if score>=60 else "Review sender and links before responding", "Do not open links until verified through an official channel"]

def analyze_login(data):
    score=10; evidence=[]
    outcome=str(data.get("outcome","success")).lower(); country=str(data.get("country","")); device=str(data.get("device","")); failures=int(data.get("failed_attempts",0) or 0)
    if failures>=5: score+=30; evidence.append(f"{failures} failed attempts observed")
    elif failures>=3: score+=18; evidence.append(f"{failures} failed attempts observed")
    if str(data.get("new_device","false")).lower() in ("true","1","yes"): score+=24; evidence.append("Device is new for this account")
    if str(data.get("new_location","false")).lower() in ("true","1","yes"): score+=25; evidence.append("Location differs from the account baseline")
    if outcome not in ("success","successful","succeeded","true"): score+=12; evidence.append("Login attempt was unsuccessful")
    if not country and not device: evidence.append("Limited context supplied; location and device baselines are unavailable")
    if not evidence: evidence=["No unusual indicators in the supplied login fields"]
    score=min(score,100); level="Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=35 else "Low"
    verdict="Suspicious login" if score>=60 else "Needs review" if score>=35 else "No obvious anomaly"
    return score,level,verdict,evidence,["Verify the activity with the account owner", "If unrecognized, revoke sessions and reset credentials through the approved identity provider"]

def save_event(kind,title,detail,actor,result):
    score,level,verdict,evidence,recs=result; eid=str(uuid.uuid4()); now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    with connect() as db: db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,'Open')",(eid,kind,title,detail,actor or "Unassigned",now,score,level,verdict,json.dumps(evidence),json.dumps(recs)))
    return eid

def row_event(r):
    d=dict(r); d["evidence"]=json.loads(d["evidence"]); d["recommendations"]=json.loads(d["recommendations"]); return d

google_mail.set_email_analyzer(analyze_email)

class Handler(BaseHTTPRequestHandler):
    server_version="PhishGuard/1.0"
    def log_message(self,*args): pass
    def send_json(self,status,obj):
        raw=json.dumps(obj).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw)
    def body(self):
        n=int(self.headers.get("Content-Length","0")); return json.loads(self.rfile.read(n) or b"{}")
    def do_GET(self):
        parsed=urllib.parse.urlparse(self.path); path=parsed.path
        if path=="/auth/google/start":
            try:
                self.send_response(302); self.send_header("Location",google_mail.create_authorization_url()); self.send_header("Cache-Control","no-store"); self.end_headers()
            except Exception as exc:
                self.send_response(302); self.send_header("Location","/?auth_error="+urllib.parse.quote(str(exc))); self.end_headers()
            return
        if path=="/oauth2callback" or (path=="/" and ("code" in urllib.parse.parse_qs(parsed.query) or "error" in urllib.parse.parse_qs(parsed.query))):
            query=urllib.parse.parse_qs(parsed.query)
            if query.get("error"):
                destination="/?auth_error="+urllib.parse.quote(query["error"][0])
            else:
                try:
                    google_mail.finish_authorization(query.get("code",[""])[0],query.get("state",[""])[0])
                    destination="/?google_connected=1"
                except Exception as exc:
                    destination="/?auth_error="+urllib.parse.quote(str(exc))
            self.send_response(302); self.send_header("Location",destination); self.send_header("Cache-Control","no-store"); self.end_headers(); return
        if path.startswith("/api/"): return self.api_get(path)
        file="index.html" if path=="/" else path.lstrip("/")
        target=(STATIC/file).resolve()
        if not str(target).startswith(str(STATIC.resolve())) or not target.is_file(): return self.send_error(404)
        data=target.read_bytes(); typ="text/html" if target.suffix==".html" else "text/css" if target.suffix==".css" else "application/javascript" if target.suffix==".js" else "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type",typ+"; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def api_get(self,path):
        if path=="/api/v1/auth/status": return self.send_json(200,google_mail.status())
        if path=="/api/v1/gmail/messages":
            try: return self.send_json(200,{"messages":google_mail.list_messages(30),"email":google_mail.status().get("email")})
            except Exception as exc: return self.send_json(401,{"error":str(exc)})
        if path.startswith("/api/v1/gmail/messages/"):
            try: return self.send_json(200,{"message":google_mail.get_message(urllib.parse.unquote(path.rsplit("/",1)[-1]))})
            except Exception as exc: return self.send_json(404,{"error":str(exc)})
        with connect() as db:
            if path=="/api/v1/events": return self.send_json(200,{"events":[row_event(r) for r in db.execute("SELECT * FROM events ORDER BY created DESC").fetchall()]})
            if path=="/api/v1/dashboard/summary":
                rows=db.execute("SELECT kind,score,status FROM events").fetchall(); return self.send_json(200,{"total":len(rows),"high":sum(r['score']>=60 for r in rows),"open":sum(r['status']=='Open' for r in rows),"emails":sum(r['kind']=='email' for r in rows),"logins":sum(r['kind']=='login' for r in rows),"qrs":sum(r['kind']=='qr' for r in rows)})
            if path.startswith("/api/v1/events/"):
                eid=path.split("/")[-1]; row=db.execute("SELECT * FROM events WHERE id=?",(eid,)).fetchone()
                if not row: return self.send_json(404,{"error":"Event not found"})
                actions=[dict(a) for a in db.execute("SELECT * FROM actions WHERE event_id=? ORDER BY created DESC",(eid,))]; return self.send_json(200,{"event":row_event(row),"actions":actions})
        return self.send_json(404,{"error":"Unknown route"})
    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path; data=self.body()
        if path=="/api/v1/auth/signout":
            google_mail.sign_out(); return self.send_json(200,{"ok":True})
        if path=="/api/v1/analyze/email":
            result=analyze_email(data); eid=save_event("email",data.get("subject") or "Email investigation",data.get("body",""),data.get("sender"),result); return self.send_json(201,{"event_id":eid,"score":result[0],"level":result[1],"verdict":result[2],"evidence":result[3],"recommendations":result[4]})
        if path=="/api/v1/analyze/login":
            result=analyze_login(data); eid=save_event("login","Login activity",json.dumps(data),data.get("user"),result); return self.send_json(201,{"event_id":eid,"score":result[0],"level":result[1],"verdict":result[2],"evidence":result[3],"recommendations":result[4]})
        if path=="/api/v1/logins/import":
            rows=data.get("events",[])
            if not isinstance(rows,list) or len(rows)>2000: return self.send_json(400,{"error":"Provide a list of at most 2,000 login rows"})
            saved=[]
            for row in rows:
                result=analyze_login(row); eid=save_event("login","Imported login activity",json.dumps(row),row.get("user"),result); saved.append(eid)
            return self.send_json(201,{"imported":len(saved),"event_ids":saved})
        if path=="/api/v1/analyze/qr":
            payload=str(data.get("payload", "")); image_name=str(data.get("filename","QR image")); evidence=[]; score=8
            if not payload: score=55; evidence=["No QR code could be decoded from the image; it may be invalid, damaged, or unsupported"]
            elif payload.lower().startswith(("javascript:","data:","file:","vbscript:")): score=95; evidence=["QR payload uses a dangerous or unsupported active-content scheme"]
            elif payload.startswith(("http://","https://")):
                flags=classify_url(payload); evidence=flags or ["Decoded URL; no obvious risk indicators detected"]
                score=min(95,12+28*len(flags))
            else:
                evidence=["QR code contains non-URL text; verify its source and intended use"]
                score=22 if len(payload)<300 else 40
            level="Critical" if score>=80 else "High" if score>=60 else "Medium" if score>=35 else "Low"; verdict="Potentially harmful QR" if score>=60 else "Needs review" if score>=35 else "QR analyzed"
            recs=["Do not open or act on the decoded content until its source is verified", "Use the official website or app directly instead of scanning an untrusted code"]
            eid=save_event("qr",image_name,payload or "No payload decoded",data.get("submitted_by"), (score,level,verdict,evidence,recs)); return self.send_json(201,{"event_id":eid,"score":score,"level":level,"verdict":verdict,"payload":payload,"evidence":evidence,"recommendations":recs})
        if path.startswith("/api/v1/incidents/") and path.endswith("/actions"):
            eid=path.split("/")[-2]; aid=str(uuid.uuid4()); now=datetime.datetime.now(datetime.timezone.utc).isoformat(); action=str(data.get("action","Review")); note=str(data.get("note",""))
            with connect() as db:
                if not db.execute("SELECT 1 FROM events WHERE id=?",(eid,)).fetchone(): return self.send_json(404,{"error":"Incident not found"})
                db.execute("INSERT INTO actions VALUES(?,?,?,?,?)",(aid,eid,action,note,now))
            return self.send_json(201,{"id":aid,"event_id":eid,"action":action,"note":note,"created":now,"message":"Action recorded for review. No external response was executed."})
        if path.startswith("/api/v1/incidents/") and path.endswith("/status"):
            eid=path.split("/")[-2]; status=str(data.get("status","Open"))
            if status not in ("Open","Investigating","Resolved"): return self.send_json(400,{"error":"Invalid status"})
            with connect() as db: db.execute("UPDATE events SET status=? WHERE id=?",(status,eid))
            return self.send_json(200,{"status":status})
        if path=="/api/v1/demo/reset":
            with connect() as db: db.execute("DELETE FROM events"); db.execute("DELETE FROM actions")
            init(); return self.send_json(200,{"ok":True})
        return self.send_json(404,{"error":"Unknown route"})

if __name__=="__main__":
    init(); host="127.0.0.1"; port=8000
    print(f"PhishGuard is running at http://{host}:{port} (local mode)")
    server=ThreadingHTTPServer((host,port),Handler)
    webbrowser.open(f"http://{host}:{port}/")
    server.serve_forever()
