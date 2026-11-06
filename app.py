import os
import io
import base64
import re
import json
import urllib.request
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template_string, request, send_file, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# Trust Render's single reverse proxy for visitor IP and HTTPS scheme.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
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
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
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


class FullscreenImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_data = db.Column(db.LargeBinary, nullable=False)
    mime_type = db.Column(db.String(32), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now, onupdate=now, nullable=False)

class TrollRedirect(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

class TrollPrank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(24), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

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

@app.before_request
def deliver_pending_troll_redirect():
    user = current_user()
    if not user or user.is_admin or request.method != "GET":
        return None
    if request.endpoint in ("screen_page", "screen_image", "logout", "login", "register", "locked", "static", "prank_check"):
        return None
    pending = TrollRedirect.query.filter_by(user_id=user.id).first()
    if pending:
        db.session.delete(pending)
        db.session.commit()
        return redirect(url_for("screen_page"))
    prank = TrollPrank.query.filter_by(user_id=user.id).first()
    if prank and request.endpoint != "prank_page":
        session["pending_prank"] = prank.kind
        db.session.delete(prank)
        db.session.commit()
        return redirect(url_for("prank_page"))
    return None

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
.troll-menu summary{display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;list-style:none}.troll-menu summary::-webkit-details-marker{display:none}.troll-menu summary:after{content:"＋";font-size:20px;color:#9fc9ff}.troll-menu[open] summary:after{content:"−"}.troll-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.troll-choice{min-width:0;padding:10px;border:1px solid #26364c;border-radius:10px;background:#101a2a}.troll-choice button{margin:0 0 5px;text-align:left;font-size:14px;padding:10px}.troll-choice small{display:block;line-height:1.35}.troll-menu .tag{font-size:10px;text-align:right}@media(max-width:520px){main{margin:12px auto;padding:16px}.troll-grid{grid-template-columns:1fr}.troll-menu summary{align-items:flex-start;flex-direction:column}}
small{color:#9ba9bd}.tag{font-size:12px;color:#9fc9ff}hr{border:0;border-top:1px solid #26364c;margin:22px 0}
</style></head><body><main>
<h1>RASPB <span class="tag">CONSOLE</span></h1><div class="muted">Shared access â¢ owner-managed â¢ private notices</div>
{% with items = get_flashed_messages(with_categories=true) %}{% for category, message in items %}<p class="{{ category }}">{{ message }}</p>{% endfor %}{% endwith %}
{{ content|safe }}
</main><script>(()=>{if(location.pathname==='/prank')return;let busy=false;const check=async()=>{if(busy||document.hidden)return;busy=true;try{const r=await fetch('/prank/check',{credentials:'same-origin',cache:'no-store'});if(r.ok){const d=await r.json();if(d.go){location.href='/prank';return;}}}catch(e){}finally{busy=false;}};setInterval(check,1800);check();})();</script>
</body></html>
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
    <p><a href="{{ url_for('login') }}">Log in</a> Â· <a href="{{ url_for('register') }}">Create account</a></p>
    """)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        owner_name = os.environ.get("OWNER_USERNAME", "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
            flash("Username must be 3â32 characters: letters, numbers or underscores.", "error")
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
    {% for u in users %}<div class="panel"><b>{{ u.username }}</b> Â· {% if u.is_locked %}<span class="error">LOCKED</span>{% else %}<span class="success">ACTIVE</span>{% endif %}
    <p><small>Joined: {{ u.created_at }} Â· Last login: {{ u.last_login or "Never" }}</small></p>
    {% if u.is_locked %}<form method="post" action="{{ url_for('unlock_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Unlock account</button></form>
    {% else %}<form method="post" action="{{ url_for('lock_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><textarea name="message" maxlength="500" placeholder="Private message explaining the lock..." required></textarea><button class="danger">Lock and send private message</button></form>{% endif %}
    <form method="post" action="{{ url_for('message_user', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input name="message" maxlength="500" placeholder="Send a private message (optional)" required><button class="secondary">Send private message</button></form>
    <form method="post" action="{{ url_for('send_troll', user_id=u.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Open fullscreen display once</button></form>
     <details class="panel troll-menu"><summary><b>Trolls</b><span class="tag">13 VISUAL EFFECTS · TAP TO CHOOSE</span></summary>\n     <p class="muted">Pick one effect for this account. It runs only inside the site, lasts 9 seconds, and has an Exit button.</p><div class="troll-grid">\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/shadow"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Shadow figure</button><small>A silhouette slowly appears.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/eyes"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Watching eyes</button><small>Two eyes blink in the dark.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/terminal"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Haunted terminal</button><small>A fake system log types itself.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/presence"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Behind you</button><small>A shadow moves across the screen.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/nightmare"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Corrupted nightmare</button><small>A brief distorted warning scene.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/static"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Static storm</button><small>Animated TV-style interference.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/moon"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Red moon</button><small>A glowing red moon pulses.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/echo"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Echo presence</button><small>A large flickering message appears.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/bars"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Frequency shift</button><small>Signal bars pulse across the screen.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/glitch"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Glitch burst</button><small>RGB split and screen jitter.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/fog"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Ghost fog</button><small>Soft fog drifts across the display.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/fracture"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">Shattered mirror</button><small>A fractured-text visual effect.</small></form>\n     <form class="troll-choice" method="post" action="/admin/prank/{{ u.id }}/void"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="secondary">The void</button><small>A dark animated vignette.</small></form>\n     </div></details></div>{% endfor %}

    <h2>Fullscreen screen</h2><div class="panel"><p class="muted">Upload an image to display publicly at <a href="{{ url_for('screen_page') }}" target="_blank">/screen</a>. Maximum 8 MB. PNG, JPG, WebP or GIF.</p>
    <form method="post" action="{{ url_for('upload_fullscreen_image') }}" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="file" name="image" accept="image/png,image/jpeg,image/webp,image/gif" required><button>Upload / replace screen image</button></form>
    <p><a href="{{ url_for('screen_page') }}" target="_blank">Open public fullscreen screen</a></p></div>
    <h2>Recent login history</h2>{% for u in users %}{% for e in u.login_events[-5:] %}<p><small>{{ u.username }} Â· {{ e.created_at }}</small></p>{% endfor %}{% endfor %}
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


@app.post("/admin/troll/<int:user_id>")
@owner_required
def send_troll(user_id):
    target = db.session.get(User, user_id)
    image = db.session.get(FullscreenImage, 1)
    if not target or target.is_admin:
        flash("Choose a regular member account.", "error")
    elif image is None:
        flash("Upload the troll image first in Fullscreen screen.", "error")
    else:
        pending = TrollRedirect.query.filter_by(user_id=target.id).first()
        if pending is None:
            db.session.add(TrollRedirect(user_id=target.id))
            db.session.commit()
        flash("One-time troll redirect queued for " + target.username + ". It happens on their next page visit.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/prank/<int:user_id>/<kind>")
@owner_required
def queue_prank(user_id, kind):
    allowed = ("shadow", "eyes", "terminal", "presence", "nightmare", "static", "moon", "echo", "bars", "glitch", "fog", "fracture", "void")
    target = db.session.get(User, user_id)
    if not target or target.is_admin or kind not in allowed:
        flash("Choose a regular member and a valid prank.", "error")
    else:
        prank = TrollPrank.query.filter_by(user_id=target.id).first()
        if prank is None:
            db.session.add(TrollPrank(user_id=target.id, kind=kind))
        else:
            prank.kind = kind
            prank.created_at = now()
        db.session.commit()
        flash("Visual effect queued for " + target.username + ". It starts automatically while they are signed in and ends automatically.", "success")
    return redirect(url_for("admin"))

@app.route("/prank/check")
@login_required
def prank_check():
    user = current_user()
    if not user or user.is_admin:
        return {"go": False}
    prank = TrollPrank.query.filter_by(user_id=user.id).first()
    if not prank:
        return {"go": False}
    session["pending_prank"] = prank.kind
    db.session.delete(prank)
    db.session.commit()
    return {"go": True}

@app.route("/prank")
@login_required
def prank_page():
    kind = session.pop("pending_prank", None)
    if kind not in ("shadow", "eyes", "terminal", "presence", "nightmare", "static", "moon", "echo", "bars", "glitch", "fog", "fracture", "void"):
        return redirect(url_for("dashboard"))
    html = base64.b64decode("PCFkb2N0eXBlIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgY2hhcnNldD0idXRmLTgiPjxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsaW5pdGlhbC1zY2FsZT0xIj48dGl0bGU+UkFTUEIgLy8gU0lHTkFMPC90aXRsZT48c3R5bGU+Kntib3gtc2l6aW5nOmJvcmRlci1ib3h9aHRtbCxib2R5e21hcmdpbjowO3dpZHRoOjEwMCU7aGVpZ2h0OjEwMCU7YmFja2dyb3VuZDojMDMwNDA3O2NvbG9yOiNkZGQ7Zm9udDoxNnB4IHN5c3RlbS11aTtvdmVyZmxvdzpoaWRkZW59Ym9keXtkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO2JhY2tncm91bmQ6cmFkaWFsLWdyYWRpZW50KGVsbGlwc2UsIzE4MTMxYiwjMDAwIDc1JSl9I3NjZW5le3Bvc2l0aW9uOnJlbGF0aXZlO3dpZHRoOjEwMHZ3O2hlaWdodDoxMDB2aDtkaXNwbGF5OmdyaWQ7cGxhY2UtaXRlbXM6Y2VudGVyO3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6MjRweH1oMXtmb250LXNpemU6Y2xhbXAoMjhweCw3dncsNjRweCk7bGV0dGVyLXNwYWNpbmc6LjEyZW07dGV4dC1zaGFkb3c6MCAwIDIycHggIzljMjMzY31we2NvbG9yOiNhYWF9LmV4aXR7cG9zaXRpb246Zml4ZWQ7Ym90dG9tOjE4cHg7cmlnaHQ6MThweDt6LWluZGV4Ojk7YmFja2dyb3VuZDojMjIyO2NvbG9yOiNlZWU7cGFkZGluZzoxMnB4IDE2cHg7Ym9yZGVyOjFweCBzb2xpZCAjNjY2O2JvcmRlci1yYWRpdXM6OXB4fS50aW1lcntwb3NpdGlvbjpmaXhlZDtib3R0b206MThweDtsZWZ0OjE4cHg7Y29sb3I6Izc3Nztmb250OjEycHggbW9ub3NwYWNlfS5zaGFkb3d7cG9zaXRpb246YWJzb2x1dGU7d2lkdGg6MTIwcHg7aGVpZ2h0OjI3MHB4O2JvdHRvbTo4JTtsZWZ0OjUwJTt0cmFuc2Zvcm06dHJhbnNsYXRlWCgtNTAlKTtiYWNrZ3JvdW5kOiMwMDA7Ym9yZGVyLXJhZGl1czo0OCUgNDglIDEyJSAxMiU7Ym94LXNoYWRvdzowIDAgOTBweCA0NXB4ICMwMDA7YW5pbWF0aW9uOmxvb20gNHMgZWFzZS1pbi1vdXQgaW5maW5pdGUgYWx0ZXJuYXRlO3otaW5kZXg6LTF9LnNoYWRvdzpiZWZvcmV7Y29udGVudDoiIjtwb3NpdGlvbjphYnNvbHV0ZTt3aWR0aDoxNTBweDtoZWlnaHQ6MTIwcHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDojMDAwO3RvcDotNTVweDtsZWZ0Oi0xNXB4fS5leWV7cG9zaXRpb246YWJzb2x1dGU7dG9wOjM4JTt3aWR0aDoxOHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDojZmYyNjNlO2JveC1zaGFkb3c6MCAwIDIycHggOHB4ICNlMDAwMjU7YW5pbWF0aW9uOmJsaW5rIDMuNXMgaW5maW5pdGV9LmxlZnR7bGVmdDpjYWxjKDUwJSAtIDM0cHgpfS5yaWdodHtsZWZ0OmNhbGMoNTAlICsgMTZweCl9QGtleWZyYW1lcyBibGlua3swJSw0MiUsNDYlLDEwMCV7b3BhY2l0eToxfTQ0JXtvcGFjaXR5OjB9fUBrZXlmcmFtZXMgbG9vbXtmcm9te3RyYW5zZm9ybTp0cmFuc2xhdGVYKC01MCUpIHNjYWxlKC43NSl9dG97dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTUwJSkgc2NhbGUoMS4zKX19LnRlcm1pbmFse2ZvbnQ6MTRweC8xLjggbW9ub3NwYWNlO2NvbG9yOiNiNmU3YzU7dGV4dC1hbGlnbjpsZWZ0O3doaXRlLXNwYWNlOnByZS13cmFwfS5mbGlja2Vye2FuaW1hdGlvbjpmbGlja2VyIC4xNnMgaW5maW5pdGUgYWx0ZXJuYXRlfUBrZXlmcmFtZXMgZmxpY2tlcntmcm9te29wYWNpdHk6LjM1fXRve29wYWNpdHk6MX19Lndhcm5pbmd7Zm9udDpjbGFtcCgxNHB4LDN2dywyMHB4KSBtb25vc3BhY2U7Y29sb3I6I2U2NWM3MDtsZXR0ZXItc3BhY2luZzouMThlbX0uc3RhdGlje3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7b3BhY2l0eTouMjtiYWNrZ3JvdW5kOnJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoMGRlZywjZmZmIDAgMXB4LHRyYW5zcGFyZW50IDFweCA0cHgpO2FuaW1hdGlvbjpmbGlja2VyIC4xcyBpbmZpbml0ZSBhbHRlcm5hdGV9Lm1vb257d2lkdGg6MjIwcHg7aGVpZ2h0OjIyMHB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6cmFkaWFsLWdyYWRpZW50KGNpcmNsZSBhdCAzNSUgMzUlLCNmZmI0YTIsI2ExMGQyOCA2NSUsIzI0MDAwYSk7Ym94LXNoYWRvdzowIDAgOTBweCAjYTEwZDI4ODg7YW5pbWF0aW9uOmxvb20gNHMgaW5maW5pdGUgYWx0ZXJuYXRlfS5lY2hve2ZvbnQtc2l6ZTpjbGFtcCgzMnB4LDh2dyw3NnB4KTt0ZXh0LXNoYWRvdzo0cHggMCAjZTIzLC00cHggMCAjMjlmO2FuaW1hdGlvbjpmbGlja2VyIC4ycyBpbmZpbml0ZSBhbHRlcm5hdGV9LmJhcnN7Zm9udDo0MHB4IG1vbm9zcGFjZTtsZXR0ZXItc3BhY2luZzouNGVtO2FuaW1hdGlvbjpibGluayAuNXMgaW5maW5pdGUgYWx0ZXJuYXRlfS5nbGl0Y2h7Zm9udC1zaXplOmNsYW1wKDM0cHgsOXZ3LDg4cHgpO2ZvbnQtd2VpZ2h0OjkwMDtsZXR0ZXItc3BhY2luZzouMTJlbTtjb2xvcjojZWVlO3RleHQtc2hhZG93OjVweCAwICNlMzQsLTVweCAwICMzOGY7YW5pbWF0aW9uOmdsaXRjaG1vdmUgLjEycyBpbmZpbml0ZSBhbHRlcm5hdGV9QGtleWZyYW1lcyBnbGl0Y2htb3ZlezAle3RyYW5zZm9ybTp0cmFuc2xhdGUoMCl9MjUle3RyYW5zZm9ybTp0cmFuc2xhdGUoM3B4LC0ycHgpfTUwJXt0cmFuc2Zvcm06dHJhbnNsYXRlKC0zcHgsMnB4KX0xMDAle3RyYW5zZm9ybTp0cmFuc2xhdGUoMXB4LDFweCl9fS5mb2d7cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6LTIwJTtiYWNrZ3JvdW5kOnJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDIwJSA1MCUsI2FhYTUsdHJhbnNwYXJlbnQgNDUlKSxyYWRpYWwtZ3JhZGllbnQoZWxsaXBzZSBhdCA3NSUgNDUlLCNkZGQ0LHRyYW5zcGFyZW50IDQ4JSk7ZmlsdGVyOmJsdXIoMjJweCk7YW5pbWF0aW9uOmZvZ21vdmUgNXMgZWFzZS1pbi1vdXQgaW5maW5pdGUgYWx0ZXJuYXRlfUBrZXlmcmFtZXMgZm9nbW92ZXtmcm9te3RyYW5zZm9ybTp0cmFuc2xhdGVYKC04JSl9dG97dHJhbnNmb3JtOnRyYW5zbGF0ZVgoOCUpfX0uZnJhY3R1cmV7Zm9udC1zaXplOmNsYW1wKDM4cHgsMTB2dywxMDBweCk7Y29sb3I6I2RkZDt0ZXh0LXNoYWRvdzowIDAgMnB4ICNmZmYsM3B4IDNweCAjNTU1LC0zcHggLTJweCAjNzc3O2FuaW1hdGlvbjpmbGlja2VyIC4yNXMgaW5maW5pdGUgYWx0ZXJuYXRlfS52b2lke3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7YmFja2dyb3VuZDpyYWRpYWwtZ3JhZGllbnQoY2lyY2xlLCMwMDAgMCAxOCUsIzE4MGIyMCA0MiUsIzAwMCA3MiUpO2FuaW1hdGlvbjp2b2lkcHVsc2UgM3MgZWFzZS1pbi1vdXQgaW5maW5pdGUgYWx0ZXJuYXRlfUBrZXlmcmFtZXMgdm9pZHB1bHNle2Zyb217dHJhbnNmb3JtOnNjYWxlKC45NCk7b3BhY2l0eTouN310b3t0cmFuc2Zvcm06c2NhbGUoMS4wOCk7b3BhY2l0eToxfX08L3N0eWxlPjwvaGVhZD48Ym9keT48ZGl2IGlkPSJzY2VuZSI+eyUgaWYga2luZCA9PSAnc2hhZG93JyAlfTxkaXYgY2xhc3M9InNoYWRvdyI+PC9kaXY+PGgxPkRPTidUIExPT0sgQVdBWTwvaDE+PHA+U29tZXRoaW5nIG1vdmVkIGluIHRoZSBkYXJrLjwvcD57JSBlbGlmIGtpbmQgPT0gJ2V5ZXMnICV9PGRpdiBjbGFzcz0iZXllIGxlZnQiPjwvZGl2PjxkaXYgY2xhc3M9ImV5ZSByaWdodCI+PC9kaXY+PGgxPklUIFNFRVMgWU9VPC9oMT48cD5UaGUgZXllcyBhcmUgd2F0Y2hpbmcuPC9wPnslIGVsaWYga2luZCA9PSAndGVybWluYWwnICV9PGRpdj48ZGl2IGNsYXNzPSJ3YXJuaW5nIj5VTktOT1dOIFBST0NFU1MgREVURUNURUQ8L2Rpdj48cHJlIGNsYXNzPSJ0ZXJtaW5hbCIgaWQ9InR5cGVkIj48L3ByZT48L2Rpdj57JSBlbGlmIGtpbmQgPT0gJ3ByZXNlbmNlJyAlfTxkaXYgY2xhc3M9InNoYWRvdyIgc3R5bGU9ImhlaWdodDo2NXZoO3dpZHRoOjM2dnciPjwvZGl2PjxoMSBjbGFzcz0iZmxpY2tlciI+VEhFUkUgSVMgU09NRU9ORSBCRUhJTkQgWU9VPC9oMT48cD5BIHNoYXBlIGluIHRoZSBkYXJrbmVzcy48L3A+eyUgZWxpZiBraW5kID09ICJuaWdodG1hcmUiICV9PGRpdiBjbGFzcz0idm9pZCIgc3R5bGU9Im9wYWNpdHk6LjgiPjwvZGl2PjxoMSBjbGFzcz0iZ2xpdGNoIj5OSUdIVE1BUkU8L2gxPjxwPkEgc2hvcnQsIGRpc3RvcnRlZCBkcmVhbSBzZXF1ZW5jZS48L3A+eyUgZWxpZiBraW5kID09ICdzdGF0aWMnICV9PGRpdiBjbGFzcz0ic3RhdGljIj48L2Rpdj48aDE+Tk8gU0lHTkFMPC9oMT48cD5QaWN0dXJlIGludGVyZmVyZW5jZS48L3A+eyUgZWxpZiBraW5kID09ICdtb29uJyAlfTxkaXYgY2xhc3M9Im1vb24iPjwvZGl2PjxoMT5SRUQgTU9PTjwvaDE+PHA+VGhlIG5pZ2h0IGZlZWxzIGRpZmZlcmVudC48L3A+eyUgZWxpZiBraW5kID09ICdlY2hvJyAlfTxoMSBjbGFzcz0iZWNobyI+V0hPJ1MgVEhFUkU/PC9oMT48cD5BIHN0cmFuZ2UgZWNobyBmaWxscyB0aGUgc2NyZWVuLjwvcD57JSBlbGlmIGtpbmQgPT0gJ2JhcnMnICV9PGRpdiBjbGFzcz0iYmFycyI+4pawIOKWsSDilrAg4pawIOKWsTwvZGl2PjxoMT5GUkVRVUVOQ1kgU0hJRlQ8L2gxPjxwPlNpZ25hbCBmYWRpbmcgaW4gYW5kIG91dC48L3A+eyUgZWxpZiBraW5kID09ICdnbGl0Y2gnICV9PGgxIGNsYXNzPSJnbGl0Y2giPlJFQUxJVFkgU0hJRlQ8L2gxPjxwPlRoZSBpbWFnZSBpcyBicmVha2luZyBhcGFydC48L3A+eyUgZWxpZiBraW5kID09ICdmb2cnICV9PGRpdiBjbGFzcz0iZm9nIj48L2Rpdj48aDE+SU4gVEhFIE1JU1Q8L2gxPjxwPlNvbWV0aGluZyBtb3ZlcyB0aHJvdWdoIHRoZSBmb2cuPC9wPnslIGVsaWYga2luZCA9PSAnZnJhY3R1cmUnICV9PGgxIGNsYXNzPSJmcmFjdHVyZSI+Q1JBQ0tFRDwvaDE+PHA+TG9vayB0aHJvdWdoIHRoZSBicm9rZW4gZ2xhc3MuPC9wPnslIGVsaWYga2luZCA9PSAndm9pZCcgJX08ZGl2IGNsYXNzPSJ2b2lkIj48L2Rpdj48aDEgc3R5bGU9InotaW5kZXg6MSI+VEhFIFZPSUQ8L2gxPjxwIHN0eWxlPSJ6LWluZGV4OjEiPkEgcXVpZXQgZGFya25lc3MuPC9wPnslIGVsc2UgJX08ZGl2IGNsYXNzPSJ3YXJuaW5nIGZsaWNrZXIiPlNJR05BTCBDT1JSVVBURUQ8L2Rpdj48aDEgY2xhc3M9ImZsaWNrZXIiPldBS0UgVVA8L2gxPjxwPlZpc3VhbCBlZmZlY3QuPC9wPnslIGVuZGlmICV9PC9kaXY+PGRpdiBjbGFzcz0idGltZXIiPkFVVE8gRVhJVDogPHNwYW4gaWQ9InNlY29uZHMiPjk8L3NwYW4+czwvZGl2PjxidXR0b24gY2xhc3M9ImV4aXQiIG9uY2xpY2s9ImxvY2F0aW9uLmhyZWY9Jy9kYXNoYm9hcmQnIj5FeGl0IHNjYXJlPC9idXR0b24+PHNjcmlwdD5jb25zdCBsaW5lcz1bJ1swMDowMDowMV0gc2lnbmFsIHJlY2VpdmVkJywnWzAwOjAwOjAyXSBzb3VyY2U6IHVua25vd24nLCdbMDA6MDA6MDNdIGNoZWNraW5nIHJvb20uLi4nLCdbMDA6MDA6MDRdIG1vdmVtZW50IGRldGVjdGVkJywnWzAwOjAwOjA1XSB3YWl0Li4uJywnWzAwOjAwOjA2XSBzaWduYWwgZW5kZWQuJ107Y29uc3Qgb3V0PWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0eXBlZCcpO2xldCBpPTA7aWYob3V0KXtsZXQgdD1zZXRJbnRlcnZhbCgoKT0+e291dC50ZXh0Q29udGVudCs9bGluZXNbaSsrXSsnXFxuJztpZihpPj1saW5lcy5sZW5ndGgpY2xlYXJJbnRlcnZhbCh0KX0sNjUwKX1sZXQgbj05O2xldCBjPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZWNvbmRzJyk7bGV0IHQ9c2V0SW50ZXJ2YWwoKCk9PntjLnRleHRDb250ZW50PS0tbjtpZihuPD0wKXtjbGVhckludGVydmFsKHQpO2xvY2F0aW9uLmhyZWY9Jy9kYXNoYm9hcmQnfX0sMTAwMCk8L3NjcmlwdD48L2JvZHk+PC9odG1sPg==").decode("utf-8")
    return render_template_string(html, kind=kind)

@app.post("/admin/fullscreen-image")
@owner_required
def upload_fullscreen_image():
    uploaded = request.files.get("image")
    if not uploaded or not uploaded.filename:
        flash("Choose an image first.", "error")
        return redirect(url_for("admin"))
    data = uploaded.read(8 * 1024 * 1024 + 1)
    if not data:
        flash("The selected file is empty.", "error")
        return redirect(url_for("admin"))
    if len(data) > 8 * 1024 * 1024:
        flash("Image must be 8 MB or smaller.", "error")
        return redirect(url_for("admin"))
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        mime = "image/gif"
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        flash("Unsupported or invalid image. Use PNG, JPG, WebP or GIF.", "error")
        return redirect(url_for("admin"))
    image = db.session.get(FullscreenImage, 1)
    if image is None:
        image = FullscreenImage(id=1, image_data=data, mime_type=mime)
        db.session.add(image)
    else:
        image.image_data = data
        image.mime_type = mime
        image.updated_at = now()
    db.session.commit()
    flash("Fullscreen image uploaded. Open /screen to view it.", "success")
    return redirect(url_for("admin"))

@app.route("/screen")
def screen_page():
    image = db.session.get(FullscreenImage, 1)
    if image is None:
        return '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>RASPB Screen</title></head><body style="margin:0;background:#05070b;color:#aab6c8;display:grid;place-items:center;height:100vh;font:16px system-ui">No screen image uploaded yet.</body></html>'
    return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>RASPB Screen</title><style>*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0;overflow:hidden;background:#000}img{position:fixed;inset:0;width:100%;height:100%;object-fit:cover;display:block}</style></head><body><img src="/screen/image" alt=""></body></html>'

@app.route("/screen/image")
def screen_image():
    image = db.session.get(FullscreenImage, 1)
    if image is None:
        abort(404)
    response = send_file(io.BytesIO(image.image_data), mimetype=image.mime_type, download_name="raspb-screen", max_age=0)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

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
    result = ["DOMAIN INTELLIGENCE â " + domain, "", "DNS / RESOLUTION"]
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
    out=["IP INTELLIGENCE â "+str(addr),"Version: IPv"+str(addr.version),
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
                "Range: "+str(rd.get("startAddress","?"))+" â "+str(rd.get("endAddress","?"))]
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
    out=["WEBSITE INTELLIGENCE â "+host,"Resolved public IPs: "+", ".join(ips),"Requested URL: "+u.scheme+"://"+host+path]
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
    out = ["DNS RECORDS â " + domain]
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
        out = ["EMAIL DOMAIN INTELLIGENCE â " + domain, "Address syntax: valid format", "Mailbox existence: not tested (cannot be reliably confirmed through public DNS)."]
    else:
        domain = _valid_domain(value)
        out = ["EMAIL DOMAIN INTELLIGENCE â " + domain, "Domain input: valid"]
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
