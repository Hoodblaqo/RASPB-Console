import os
import re
import json
import urllib.request
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# Trust Render's single reverse proxy for visitor IP and HTTPS scheme.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
db_url = os.environ.get("DATABASE_URL", "sqlite:///raspb.sqlite3")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

def now():
    return datetime.now(timezone.utc)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    lock_message = db.Column(db.String(600), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    sender = db.Column(db.String(32), nullable=False)
    body = db.Column(db.String(600), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    recipient = db.relationship("User", backref=db.backref("messages", lazy=True, cascade="all, delete-orphan"))

class LoginEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    user = db.relationship("User", backref=db.backref("login_events", lazy=True, cascade="all, delete-orphan"))

def ensure_owner():
    name = os.environ.get("OWNER_USERNAME", "").strip().lower()
    password = os.environ.get("OWNER_PASSWORD", "")
    if not name or not password:
        return
    user = User.query.filter_by(username=name).first()
    if user is None:
        db.session.add(User(username=name, password_hash=generate_password_hash(password), is_admin=True))
        db.session.commit()
    elif not user.is_admin:
        user.is_admin = True
        db.session.commit()

with app.app_context():
    db.create_all()
    ensure_owner()

def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user.is_locked and request.endpoint not in ("locked", "logout", "static"):
            return redirect(url_for("locked"))
        return fn(*args, **kwargs)
    return wrapped

def owner_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            flash("Owner access only.", "error")
            return redirect(url_for("home"))
        return fn(*args, **kwargs)
    return wrapped

BASE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASPB Console</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif;background:#080b12;color:#e9eef8}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#17243a,#080b12 55%);min-height:100vh}
main{width:min(760px,92vw);margin:38px auto;padding:26px;background:#101725;border:1px solid #26364c;border-radius:18px;box-shadow:0 18px 60px #0008}
h1{margin:0 0 6px;letter-spacing:.08em}h2{margin-top:28px;color:#a8c7ff}.muted{color:#9ba9bd}
input,textarea,button{width:100%;padding:12px;margin:7px 0;border-radius:10px;border:1px solid #34445c;background:#0a111d;color:#f4f7fb;font:inherit}
textarea{min-height:90px;resize:vertical}button{background:#1c4b83;border:0;font-weight:700;cursor:pointer}button.danger{background:#8c2939}button.secondary{background:#34445c}
a{color:#8fc5ff}.panel{padding:15px;margin:12px 0;background:#0b1220;border:1px solid #26364c;border-radius:12px}
.notice{padding:12px;border-radius:10px;background:#312b16;margin:10px 0}.error{color:#ff9aab}.success{color:#9ce7bb}
small{color:#9ba9bd}.tag{font-size:12px;color:#9fc9ff}hr{border:0;border-top:1px solid #26364c;margin:22px 0}
</style></head><body><main>
<h1>RASPB <span class="tag">CONSOLE</span></h1><div class="muted">Shared access • owner-managed • private notices</div>
{% with items = get_flashed_messages(with_categories=true) %}{% for category, message in items %}<p class="{{ category }}">{{ message }}</p>{% endfor %}{% endwith %}
{{ content|safe }}
</main></body></html>
"""

def page(content, **context):
    context.setdefault("current_user", current_user)
    return render_template_string(BASE, content=render_template_string(content, **context))

@app.route("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("locked" if user.is_locked else ("admin" if user.is_admin else "dashboard")))
    return page("""
    <h2>Welcome</h2><p class="muted">Sign in to your shared RASPB account, or create one for your group.</p>
    <p><a href="{{ url_for('login') }}">Log in</a> · <a href="{{ url_for('register') }}">Create account</a></p>
    """)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        owner_name = os.environ.get("OWNER_USERNAME", "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
            flash("Username must be 3–32 characters: letters, numbers or underscores.", "error")
        elif username == owner_name:
            flash("That username is reserved.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        else:
            user = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session["uid"] = user.id
            flash("Account created.", "success")
            return redirect(url_for("dashboard"))
    return page("""
    <h2>Create account</h2><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="username" placeholder="Username" minlength="3" maxlength="32" required>
    <input name="password" type="password" placeholder="Password (8+ characters)" minlength="8" required>
    <button>Create account</button></form><a href="{{ url_for('login') }}">Already registered? Log in</a>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["uid"] = user.id
            user.last_login = now()
            db.session.add(LoginEvent(user_id=user.id))
            db.session.commit()
            return redirect(url_for("locked" if user.is_locked else ("admin" if user.is_admin else "dashboard")))
        flash("Incorrect username or password.", "error")
    return page("""
    <h2>Log in</h2><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="username" placeholder="Username" required autocomplete="username">
    <input name="password" type="password" placeholder="Password" required autocomplete="current-password">
    <button>Log in</button></form><a href="{{ url_for('register') }}">Create an account</a>
    """)

@app.route("/locked")
@login_required
def locked():
    user = current_user()
    if not user.is_locked:
        return redirect(url_for("home"))
    return page("""
    <div class="notice"><h2>Account locked</h2><p>Your access has been paused by the owner.</p>
    <strong>Private message from the owner:</strong><p>{{ user.lock_message or "No reason was provided." }}</p>
    </div><p class="muted">Only the owner can unlock this account. You can sign out below.</p>
    <a href="{{ url_for('logout') }}">Log out</a>
    """, user=user)

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    messages = PrivateMessage.query.filter_by(recipient_id=user.id).order_by(PrivateMessage.created_at.desc()).limit(30).all()
    return page("""
    <h2>Your account</h2><p><a href="{{ url_for('console_page') }}">Open RAMN terminal</a></p><div class="panel"><b>{{ user.username }}</b><p class="muted">Member since {{ user.created_at.strftime('%Y-%m-%d') }}</p></div>
    <h2>Private inbox</h2>{% if messages %}{% for m in messages %}<div class="panel"><b>From {{ m.sender }}</b><p>{{ m.body }}</p><small>{{ m.created_at }}</small></div>{% endfor %}{% else %}<p class="muted">No private messages yet.</p>{% endif %}
    <p><a href="{{ url_for('logout') }}">Log out</a></p>
    """, user=user, messages=messages)

@app.route("/admin")
@owner_required
def admin():
    users = User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()
    return page("""
    <h2>Owner panel</h2><p><a href="{{ url_for('console_page') }}">Open RAMN terminal</a></p><p class="muted">Only the configured owner account can use these controls.</p>
    {% for u in users %}<div class="panel"><b>{{ u.username }}</b> · {% if u.is_locked %}<span class="error">LOCKED</span>{% else %}<span class="success">ACTIVE</span>{% endif %}
    <p><small>Joined: {{ u.created_at }} · Last login: {{ u.last_login or "Never" }}</small></p>
    {% if u.is_locked %}<form method="post" action="{{ url_for('unlock_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Unlock account</button></form>
    {% else %}<form method="post" action="{{ url_for('lock_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><textarea name="message" maxlength="500" placeholder="Private message explaining the lock..." required></textarea><button class="danger">Lock and send private message</button></form>{% endif %}
    <form method="post" action="{{ url_for('message_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input name="message" maxlength="500" placeholder="Send a private message (optional)" required><button class="secondary">Send private message</button></form>
    </div>{% else %}<p class="muted">No member accounts yet.</p>{% endfor %}
    <h2>Recent login history</h2>{% for u in users %}{% for e in u.login_events[-5:] %}<p><small>{{ u.username }} · {{ e.created_at }}</small></p>{% endfor %}{% endfor %}
    <p><a href="{{ url_for('logout') }}">Log out</a></p>
    """, users=users)

@app.post("/admin/lock/<int:user_id>")
@owner_required
def lock_user(user_id):
    target = db.session.get(User, user_id)
    message = request.form.get("message", "").strip()
    if not target or target.is_admin:
        flash("That account cannot be locked.", "error")
    elif not message:
        flash("Add a private message before locking.", "error")
    else:
        target.is_locked = True
        target.lock_message = message[:500]
        db.session.add(PrivateMessage(recipient_id=target.id, sender=current_user().username, body="Account locked: " + message[:500]))
        db.session.commit()
        flash("Account locked and private notice sent.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/unlock/<int:user_id>")
@owner_required
def unlock_user(user_id):
    target = db.session.get(User, user_id)
    if target and not target.is_admin:
        target.is_locked = False
        target.lock_message = None
        db.session.commit()
        flash("Account unlocked.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/message/<int:user_id>")
@owner_required
def message_user(user_id):
    target = db.session.get(User, user_id)
    message = request.form.get("message", "").strip()
    if target and not target.is_admin and message:
        db.session.add(PrivateMessage(recipient_id=target.id, sender=current_user().username, body=message[:500]))
        db.session.commit()
        flash("Private message sent.", "success")
    else:
        flash("Could not send that message.", "error")
    return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.errorhandler(403)
def forbidden(_error):
    return "Forbidden", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), debug=False)



# Passive OSINT workspace. Only public DNS/RDAP/HTTP/TLS metadata is queried.
import ipaddress
import socket
import ssl
import urllib.parse
import urllib.error
import urllib.request
from html.parser import HTMLParser

def _valid_domain(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Enter a valid domain name.")
    if "." not in value or any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):
        raise ValueError("Enter a fully qualified domain such as example.com.")
    return value

def _public_host(host):
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private, reserved, and local IP addresses are not queried.")
        return [str(ip)]
    except ValueError as exc:
        if "not queried" in str(exc):
            raise
    try:
        rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({row[4][0] for row in rows})
    except Exception:
        raise ValueError("The domain could not be resolved.")
    if not addresses:
        raise ValueError("No public address was found.")
    for item in addresses:
        if not ipaddress.ip_address(item).is_global:
            raise ValueError("The domain resolves to a non-public address; request blocked.")
    return addresses

def _get_json(url, timeout=7):
    req = urllib.request.Request(url, headers={"User-Agent":"RASPB-OSINT/1.0","Accept":"application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        if res.status != 200:
            raise ValueError("The information provider returned HTTP " + str(res.status))
        return json.loads(res.read(900000).decode("utf-8", "replace"))

def _doh(name, kind):
    q = urllib.parse.urlencode({"name":name,"type":kind})
    data = _get_json("https://cloudflare-dns.com/dns-query?"+q)
    return [x.get("data","") for x in data.get("Answer",[]) if x.get("data")]

def _rdap(url):
    try:
        data = _get_json(url, timeout=8)
        return data
    except Exception as exc:
        raise ValueError("RDAP lookup unavailable: " + str(exc)[:140])

def _domain_report(raw):
    domain = _valid_domain(raw)
    result = ["DOMAIN INTELLIGENCE — " + domain, "", "DNS / RESOLUTION"]
    for kind in ("A", "AAAA"):
        try:
            vals = _doh(domain, kind)
            result.append(kind + ": " + (" | ".join(vals[:12]) if vals else "No records returned"))
        except Exception:
            result.append(kind + ": lookup unavailable")
    for kind in ("MX", "NS", "TXT", "CAA"):
        try:
            vals = _doh(domain, kind)
            result.append(kind + ": " + (" | ".join(vals[:12]) if vals else "No records returned"))
        except Exception:
            result.append(kind + ": lookup unavailable")
    try:
        rd = _rdap("https://rdap.org/domain/" + urllib.parse.quote(domain))
        result += ["", "REGISTRATION (RDAP)", "Handle: " + str(rd.get("handle") or "Not supplied"),
                   "Status: " + ", ".join(rd.get("status", [])[:8])]
        events = [e.get("eventDate", "") for e in rd.get("events", []) if e.get("eventAction") in ("registration", "expiration", "last changed")]
        if events: result.append("Registration events: " + " | ".join(events[:5]))
        names = [n.get("ldhName", "") for n in rd.get("nameservers", []) if n.get("ldhName")]
        if names: result.append("Nameservers: " + ", ".join(names[:8]))
        result.append("Registrar: " + next((v.get("fn", "") for ent in rd.get("entities", []) if "registrar" in ent.get("roles", []) for v in ent.get("vcardArray", [[], []])[1] if len(v) > 3 and v[0] == "fn"), "Not supplied"))
    except Exception as exc:
        result += ["", "REGISTRATION (RDAP)", str(exc)]
    result += ["", "Source: Cloudflare DNS-over-HTTPS and public RDAP. DNS data may be cached."]
    return result

def _ip_report(raw):
    try: addr=ipaddress.ip_address(raw.strip())
    except ValueError: raise ValueError("Enter a valid IPv4 or IPv6 address.")
    out=["IP INTELLIGENCE — "+str(addr),"Version: IPv"+str(addr.version),
         "Global/public: "+str(addr.is_global),"Private: "+str(addr.is_private),
         "Reserved: "+str(addr.is_reserved),"Loopback: "+str(addr.is_loopback)]
    if not addr.is_global:
        out.append("External geolocation skipped for non-public addresses.")
        return out
    try:
        rd=_rdap("https://rdap.org/ip/"+str(addr))
        out += ["","IP REGISTRATION (RDAP)","Network name: "+str(rd.get("name") or "Not supplied"),
                "Handle: "+str(rd.get("handle") or "Not supplied"),
                "Country: "+str(rd.get("country") or "Not supplied"),
                "Range: "+str(rd.get("startAddress","?"))+" – "+str(rd.get("endAddress","?"))]
    except Exception as exc: out += ["RDAP: "+str(exc)]
    try:
        info=_get_json("https://ipinfo.io/"+str(addr)+"/json")
        for key,label in (("hostname","Hostname"),("org","Network / ASN"),("city","City"),("region","Region"),("country","Country"),("loc","Coordinates"),("timezone","Timezone")):
            if info.get(key): out.append(label+": "+str(info[key]))
    except Exception: out.append("Geolocation provider unavailable.")
    out.append("Source: public RDAP and ipinfo.io. Location is approximate, not a street address.")
    return out

def _url_report(raw):
    raw=raw.strip()
    if "://" not in raw: raw="https://"+raw
    u=urllib.parse.urlsplit(raw)
    if u.scheme not in ("http","https") or not u.hostname or u.username or u.password:
        raise ValueError("Use a public http:// or https:// website URL.")
    if u.port not in (None,80,443): raise ValueError("Only standard web ports 80 and 443 are supported.")
    host=u.hostname.lower()
    ips=_public_host(host)
    port=u.port or (443 if u.scheme=="https" else 80)
    path=urllib.parse.urlunsplit(("", "", u.path or "/", u.query, ""))
    req=urllib.request.Request(urllib.parse.urlunsplit((u.scheme,host,path,"","")),headers={"User-Agent":"Mozilla/5.0 (compatible; RASPB-OSINT/1.0)","Range":"bytes=0-120000"},method="GET")
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener=urllib.request.build_opener(_NoRedirect,urllib.request.HTTPHandler(),urllib.request.HTTPSHandler())
    out=["WEBSITE INTELLIGENCE — "+host,"Resolved public IPs: "+", ".join(ips),"Requested URL: "+u.scheme+"://"+host+path]
    try:
        with opener.open(req,timeout=8) as res:
            body=res.read(120000).decode("utf-8","replace")
            headers=res.headers
            out += ["HTTP status: "+str(res.status),"Final URL: "+res.geturl(),"Server: "+headers.get("Server","Not disclosed"),
                    "Content-Type: "+headers.get("Content-Type","Not disclosed")]
            for h in ("strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy","permissions-policy"):
                out.append(h+": "+headers.get(h,"Not observed"))
            title=re.search(r"(?is)<title[^>]*>(.*?)</title>",body)
            if title: out.append("Page title: "+re.sub(r"\\s+"," ",re.sub(r"<[^>]+>","",title.group(1)))[:180])
            tech=[]
            for needle,label in (("wp-content","WordPress"),("Shopify","Shopify"),("Drupal.settings","Drupal"),("next/static","Next.js"),("react","React"),("cloudflare","Cloudflare")):
                if needle.lower() in body.lower() or needle.lower() in str(headers).lower(): tech.append(label)
            out.append("Technology hints: "+(", ".join(tech) if tech else "No common signature detected"))
            out.append("Redirects are not followed automatically.")
    except urllib.error.HTTPError as exc:
        out += ["HTTP status: "+str(exc.code),"Response: "+str(exc.reason)[:150]]
        if exc.headers.get("Location"): out.append("Redirect/location: "+exc.headers.get("Location")[:300])
    except Exception as exc: out.append("HTTP request failed: "+str(exc)[:180])
    out.append("Safety: public host only; standard web ports; no crawling or vulnerability exploitation.")
    return out

def _dns_report(raw):
    domain = _valid_domain(raw)
    out = ["DNS RECORDS — " + domain]
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
        try:
            vals = _doh(domain, kind)
            out.append(kind + ": " + (" | ".join(vals[:15]) if vals else "No records"))
        except Exception:
            out.append(kind + ": provider unavailable")
    out.append("Source: Cloudflare DNS-over-HTTPS.")
    return out


def _email_report(raw):
    value = raw.strip()
    if len(value) > 254:
        raise ValueError("Email address is too long.")
    if "@" in value:
        if value.count("@") != 1:
            raise ValueError("Enter an email address in name@example.com format, or enter a domain.")
        local, domain_raw = value.rsplit("@", 1)
        if (not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local
                or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)):
            raise ValueError("The email address format is invalid.")
        domain = _valid_domain(domain_raw)
        out = ["EMAIL DOMAIN INTELLIGENCE — " + domain, "Address syntax: valid format", "Mailbox existence: not tested (cannot be reliably confirmed through public DNS)."]
    else:
        domain = _valid_domain(value)
        out = ["EMAIL DOMAIN INTELLIGENCE — " + domain, "Domain input: valid"]
    try:
        mx = _doh(domain, "MX")
        out.append("MX records: " + (" | ".join(mx[:12]) if mx else "No MX records found"))
        out.append("Mail routing: " + ("MX records published" if mx else "No MX records observed; check implicit-MX/A records before concluding mail is unavailable"))
    except Exception:
        out.append("MX lookup: provider unavailable")
    try:
        txt = _doh(domain, "TXT")
        spf = [x for x in txt if "v=spf1" in x.lower()]
        out.append("SPF: " + (" | ".join(spf[:3]) if spf else "No SPF record observed"))
    except Exception:
        out.append("SPF lookup: provider unavailable")
    for name, label in (("_dmarc." + domain, "DMARC"), ("_mta-sts." + domain, "MTA-STS"), ("_smtp._tls." + domain, "TLS reporting (TLS-RPT)")):
        try:
            vals = _doh(name, "TXT")
            if label == "DMARC": vals = [x for x in vals if "v=dmarc1" in x.lower()]
            elif label == "MTA-STS": vals = [x for x in vals if "v=stsv1" in x.lower()]
            else: vals = [x for x in vals if "v=tlsrptv1" in x.lower()]
            out.append(label + ": " + (" | ".join(vals[:3]) if vals else "No matching record observed"))
        except Exception:
            out.append(label + ": lookup unavailable")
    out += ["DKIM: selector-specific; not checked because selectors are not reliably discoverable.",
            "No email was sent; no mailbox login or verification was attempted."]
    return out

@app.route("/console")
@login_required
def console_page():
    token=generate_csrf()
    previous=session.pop("osint_output",[])
    return page("""
    <style>
    .osform{display:grid;grid-template-columns:1fr;gap:8px}
    .osform select,.osform input,.osform button{width:100%;padding:14px;border-radius:10px;font:inherit}
    .osform select,.osform input{background:#0a111d;color:#f4f7fb;border:1px solid #34445c}
    .result{background:#050b12;border:1px solid #25435b;border-radius:12px;padding:14px;min-height:230px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace;color:#a9f0cb}
    </style>
    <h2>OSINT intelligence workspace</h2>
    <p class="muted">Choose a tool below, enter a target, then tap Analyze. Works without JavaScript.</p>
    <form id="osform" class="osform" method="post" action="{{ url_for('osint_api') }}">
      <input type="hidden" name="csrf_token" value="{{ token }}">
      <label for="kind">Select tool</label>
      <select name="kind" id="kind" required>
        <option value="domain">Domain profile</option>
        <option value="ip">IP intelligence</option>
        <option value="url">Website analysis</option>
        <option value="dns">DNS records</option>
        <option value="email">Email domain</option>
      </select>
      <label for="target">Target</label>
      <input id="target" name="target" placeholder="example.com or name@example.com" autocomplete="off" required>
      <button type="submit" id="run">Analyze</button>
    </form>
    <p class="muted"><small>Results come from public DNS, RDAP and IP metadata providers. No account access, private data, port scanning, crawling or exploit testing.</small></p>
    <h2>Analysis output</h2>
    <div id="result" class="result" aria-live="polite">{% for line in previous %}{{ line }}{% if not loop.last %}&#10;{% endif %}{% else %}RASPB // OSINT WORKSPACE
Ready. Select a tool and enter a target.{% endfor %}</div>
    <p><a href="{{ url_for('admin') if current_user().is_admin else url_for('dashboard') }}">Back to account</a></p>
    """,token=token,previous=previous)

@app.post("/api/osint")
@login_required
def osint_api():
    fallback=not request.is_json
    data=request.get_json(silent=True) or request.form
    kind=str(data.get("kind","domain")).lower().strip()
    target=str(data.get("target","")).strip()[:500]
    if not target:
        output=["Enter a target to analyze."]
    else:
        try:
            funcs={"domain":_domain_report,"ip":_ip_report,"url":_url_report,"dns":_dns_report,"email":_email_report}
            if kind not in funcs: raise ValueError("Unknown analysis type.")
            output=funcs[kind](target)
        except ValueError as exc: output=["Input error: "+str(exc)]
        except Exception as exc: output=["Lookup failed: "+str(exc)[:180]]
    if fallback:
        session["osint_output"]=output
        return redirect(url_for("console_page"))
    return {"output":output}
