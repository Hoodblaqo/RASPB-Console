import os
import re
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
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
    <h2>Your account</h2><div class="panel"><b>{{ user.username }}</b><p class="muted">Member since {{ user.created_at.strftime('%Y-%m-%d') }}</p></div>
    <h2>Private inbox</h2>{% if messages %}{% for m in messages %}<div class="panel"><b>From {{ m.sender }}</b><p>{{ m.body }}</p><small>{{ m.created_at }}</small></div>{% endfor %}{% else %}<p class="muted">No private messages yet.</p>{% endif %}
    <p><a href="{{ url_for('logout') }}">Log out</a></p>
    """, user=user, messages=messages)

@app.route("/admin")
@owner_required
def admin():
    users = User.query.filter_by(is_admin=False).order_by(User.username.asc()).all()
    return page("""
    <h2>Owner panel</h2><p class="muted">Only the configured owner account can use these controls.</p>
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
