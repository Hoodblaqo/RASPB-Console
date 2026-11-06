import os, hmac
from datetime import datetime, timedelta, timezone
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix

app=Flask(__name__)
app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1)
app.config["SECRET_KEY"]=os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
app.config["SESSION_COOKIE_SECURE"]=os.environ.get("COOKIE_SECURE","true").lower()=="true"
u=os.environ.get("DATABASE_URL","sqlite:///thugorange7.sqlite3")
if u.startswith("postgres://"): u=u.replace("postgres://","postgresql+psycopg://",1)
elif u.startswith("postgresql://"): u=u.replace("postgresql://","postgresql+psycopg://",1)
app.config["SQLALCHEMY_DATABASE_URI"]=u
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db=SQLAlchemy(app)
csrf=CSRFProtect(app)
def now(): return datetime.now(timezone.utc).replace(tzinfo=None)
class Visitor(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    ip_address=db.Column(db.String(64),unique=True,nullable=False,index=True)
    last_seen=db.Column(db.DateTime,default=now,index=True,nullable=False)
    visits=db.Column(db.Integer,default=1,nullable=False)
with app.app_context(): db.create_all()
def purge():
    Visitor.query.filter(Visitor.last_seen<now()-timedelta(days=7)).delete(synchronize_session=False)
    db.session.commit()
@app.before_request
def track():
    if request.endpoint!="home" or request.method!="GET" or request.cookies.get("visitor_analytics")!="yes": return
    ip=(request.remote_addr or "")[:64]
    if not ip: return
    try:
        purge()
        v=Visitor.query.filter_by(ip_address=ip).first()
        if v: v.last_seen=now(); v.visits+=1
        else: db.session.add(Visitor(ip_address=ip,last_seen=now(),visits=1))
        db.session.commit()
    except Exception: db.session.rollback()
BASE=r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#100f0d"><title>thugorange7</title><style>
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% 0,#45230f,#17120e 45%,#100f0d 80%);color:#f7f0e8;font-family:system-ui,sans-serif;min-height:100vh}a{color:inherit;text-decoration:none}.wrap{max-width:980px;width:90%;margin:auto}.top{padding:28px 0;color:#ff9a46;font-size:11px;letter-spacing:.22em;font-weight:800}.hero{min-height:580px;display:flex;align-items:center;justify-content:center;flex-direction:column;text-align:center}.eyebrow{font-size:10px;letter-spacing:.28em;color:#b78b67}.hero h1{font-size:clamp(60px,12vw,126px);letter-spacing:-.09em;line-height:1;margin:28px 0 10px}.hero h1 span,.accent{color:#ff842e}.handle{letter-spacing:.2em;color:#c8b6a5}.intro{max-width:420px;color:#a89a8d;line-height:1.7;margin:25px 0}.cta{background:#ff842e;color:#1b1008;padding:16px 25px;border-radius:5px;font-size:11px;font-weight:900;letter-spacing:.14em}.below{max-width:720px;margin:0 auto 90px;border-top:1px solid #ffffff18;padding:42px 0;display:flex;align-items:center;justify-content:space-between;gap:20px}.below h2{font-size:34px;line-height:1.1}.social{padding:20px;background:#211a15;border:1px solid #55351f;border-radius:8px}.social b{display:block}.social small{color:#a89a8d}footer{border-top:1px solid #ffffff18;padding:25px 0 35px;display:flex;gap:20px;color:#8d8176;font-size:10px;letter-spacing:.14em}footer span{margin-right:auto}.consent{position:fixed;bottom:14px;left:50%;transform:translateX(-50%);width:min(760px,calc(100% - 24px));background:#251c15;border:1px solid #70421f;padding:16px;border-radius:9px;display:flex;align-items:center;gap:18px;box-shadow:0 15px 50px #000b}.consent p,.muted{font-size:12px;line-height:1.6;color:#b7a99c}.consent form{display:flex;gap:8px;flex-shrink:0}button{border:0;border-radius:5px;padding:11px 15px;font-weight:800;cursor:pointer}.yes{background:#ff842e;color:#1b1008}.no{background:#42372e;color:white}.page{padding:60px 0}.page h1{font-size:clamp(42px,8vw,72px);letter-spacing:-.06em}.card{max-width:620px;background:#211a15;border:1px solid #55351f;border-radius:9px;padding:24px}.card input{width:100%;padding:13px;margin:8px 0 15px;background:#100e0c;color:white;border:1px solid #57402e;border-radius:5px}.visitor{padding:13px;margin:8px 0;background:#211a15;border:1px solid #44301f;border-radius:7px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}.visitor code{color:#ffb17b}.back{display:inline-block;margin:25px 0;color:#ffae72}@media(max-width:620px){.hero{min-height:500px}.below{display:block}.social{display:block}.consent{display:block}.consent form{margin-top:12px}.consent button{width:48%}}
</style></head><body><div class="wrap">{{ body|safe }}</div></body></html>"""
@app.route("/")
def home():
    choice=request.cookies.get("visitor_analytics")
    body=r"""<div class="top">● &nbsp; TIKTOK CREATOR / OFFICIAL PAGE</div><section class="hero"><div class="eyebrow">WELCOME TO MY CORNER OF THE INTERNET</div><h1>thug<span>orange</span><sup>7</sup></h1><div class="handle">@thugorange7</div><p class="intro">The official spot for my TikTok content. Catch the latest videos and follow along.</p><a class="cta" href="https://www.tiktok.com/@thugorange7" target="_blank" rel="noopener">FOLLOW ON TIKTOK ↗</a><p class="eyebrow" style="margin-top:30px">ONE HANDLE. ALL THE UPDATES.</p></section><section class="below"><div><div class="eyebrow">FIND ME</div><h2>See you on<br><span class="accent">TikTok.</span></h2></div><a class="social" href="https://www.tiktok.com/@thugorange7" target="_blank" rel="noopener"><b>♪ &nbsp; @thugorange7</b><small>Watch videos · Follow · Stay updated</small></a></section><footer><span>© thugorange7</span><a href="/privacy">PRIVACY</a><a href="/owner">OWNER</a></footer>{% if not choice %}<div class="consent"><div><b>Privacy choice</b><p>This site stores your IP address and visit time for basic statistics only if you choose Allow. Only the site owner can see it. Records are deleted after 7 days.</p></div><form method="post" action="/privacy/consent"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="yes" name="choice" value="yes">Allow</button><button class="no" name="choice" value="no">Decline</button></form></div>{% endif %}"""
    return render_template_string(BASE,body=render_template_string(body,choice=choice,token=generate_csrf()))
@app.route("/privacy")
def privacy():
    body=r"""<section class="page"><div class="eyebrow">PRIVACY</div><h1>Your data.<br><span class="accent">Your choice.</span></h1><div class="card"><p>Visitor IP addresses are stored only if you choose Allow in the privacy notice. The site owner can view those IP addresses and visit counts in the private owner page. Records are automatically deleted after 7 days.</p><p>If you choose Decline, this site does not save your IP in its visitor analytics database. The hosting provider may still process connection data to operate the website.</p><form method="post" action="/privacy/consent"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="yes" name="choice" value="yes">Allow analytics</button> <button class="no" name="choice" value="no">Decline analytics</button></form></div><a class="back" href="/">← Back</a></section>"""
    return render_template_string(BASE,body=render_template_string(body,token=generate_csrf()))
@app.route("/privacy/consent",methods=["POST"])
def consent():
    c=request.form.get("choice")
    if c not in ("yes","no"): abort(400)
    r=redirect(url_for("home")); r.set_cookie("visitor_analytics",c,max_age=2592000,secure=app.config["SESSION_COOKIE_SECURE"],httponly=True,samesite="Lax"); return r
@app.route("/owner",methods=["GET","POST"])
def owner():
    if request.method=="POST":
        u,p=os.environ.get("OWNER_USERNAME",""),os.environ.get("OWNER_PASSWORD","")
        if u and p and hmac.compare_digest(request.form.get("username","").casefold(),u.casefold()) and hmac.compare_digest(request.form.get("password",""),p):
            session["creator_owner"]=True; return redirect(url_for("owner"))
    if session.get("creator_owner") is not True:
        body=r"""<section class="page"><div class="eyebrow">PRIVATE AREA</div><h1>Owner <span class="accent">login.</span></h1><form class="card" method="post"><input type="hidden" name="csrf_token" value="{{ token }}"><label>Username</label><input name="username" required><label>Password</label><input name="password" type="password" required><button class="yes">Sign in</button></form><a class="back" href="/">← Back</a></section>"""
        return render_template_string(BASE,body=render_template_string(body,token=generate_csrf()))
    purge(); rows=Visitor.query.order_by(Visitor.last_seen.desc()).limit(250).all()
    body=r"""<section class="page"><div class="eyebrow">PRIVATE DASHBOARD</div><h1>Visitor <span class="accent">stats.</span></h1><p class="muted">Only visitors who accepted analytics appear here. IP records expire after 7 days.</p><h2>{{ rows|length }} unique IPs</h2>{% for v in rows %}<div class="visitor"><code>{{ v.ip_address }}</code><span>{{ v.visits }} visits · {{ v.last_seen.strftime('%d %b %Y %H:%M UTC') }}</span></div>{% else %}<p class="muted">No opt-in visitors yet.</p>{% endfor %}<form method="post" action="/owner/logout"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="no">Log out</button></form><a class="back" href="/">← View site</a></section>"""
    return render_template_string(BASE,body=render_template_string(body,rows=rows,token=generate_csrf()))
@app.route("/owner/logout",methods=["POST"])
def logout():
    if session.get("creator_owner") is not True: abort(403)
    session.pop("creator_owner",None); return redirect(url_for("home"))
