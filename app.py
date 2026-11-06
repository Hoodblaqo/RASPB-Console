import os, hmac, json, ipaddress, urllib.request
from datetime import datetime, timedelta, timezone
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import inspect, text

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
    visitor_name=db.Column(db.String(40),nullable=True)
    city=db.Column(db.String(100),nullable=True)
    region=db.Column(db.String(100),nullable=True)
    country=db.Column(db.String(100),nullable=True)
with app.app_context():
    db.create_all()
    cols={c['name'] for c in inspect(db.engine).get_columns(Visitor.__tablename__)}
    with db.engine.begin() as conn:
        for col, typ in [('visitor_name','VARCHAR(40)'),('city','VARCHAR(100)'),('region','VARCHAR(100)'),('country','VARCHAR(100)')]:
            if col not in cols: conn.execute(text(f'ALTER TABLE visitor ADD COLUMN {col} {typ}'))
def locate(ip):
    try:
        if not ipaddress.ip_address(ip).is_global: return None, None, None
        req=urllib.request.Request('https://ipwho.is/'+ip,headers={'User-Agent':'thugorange7-site/1.0'})
        with urllib.request.urlopen(req,timeout=2) as response: data=json.loads(response.read(12000))
        if not data.get('success',True): return None,None,None
        return (str(data.get('city') or '')[:100] or None, str(data.get('region') or '')[:100] or None, str(data.get('country') or '')[:100] or None)
    except Exception: return None,None,None
def add_location(v):
    if not v.city and not v.region and not v.country:
        v.city,v.region,v.country=locate(v.ip_address)
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
        if v: v.last_seen=now(); v.visits+=1; add_location(v)
        else:
            v=Visitor(ip_address=ip,last_seen=now(),visits=1); add_location(v); db.session.add(v)
        db.session.commit()
    except Exception: db.session.rollback()
BASE=r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#100f0d"><title>thugorange7</title><style>*{box-sizing:border-box}body{margin:0;background:#f5f5f3;color:#222;font-family:Arial,Helvetica,sans-serif;min-height:100vh}a{color:inherit;text-decoration:none}.wrap{max-width:920px;width:90%;margin:auto}.top{padding:26px 0;border-bottom:1px solid #ddd;color:#555;font-size:12px;letter-spacing:.08em}.hero{min-height:490px;display:flex;align-items:flex-start;justify-content:center;flex-direction:column;text-align:left;max-width:680px;margin:auto}.eyebrow{font-size:11px;letter-spacing:.12em;color:#777}.hero h1{font-size:clamp(48px,10vw,88px);letter-spacing:-.065em;line-height:1;margin:20px 0 8px}.hero h1 span,.accent{color:#e87528}.handle{color:#777;font-size:15px}.intro{max-width:440px;color:#666;line-height:1.7;margin:22px 0}.cta{display:inline-block;background:#222;color:#fff;padding:14px 20px;border-radius:4px;font-size:12px;font-weight:700}.below{max-width:680px;margin:0 auto 70px;border-top:1px solid #ddd;padding:30px 0;display:flex;align-items:center;justify-content:space-between;gap:20px}.below h2{font-size:28px;line-height:1.2}.social{padding:17px;background:#fff;border:1px solid #ddd;border-radius:6px}.social b{display:block}.social small{color:#777}footer{border-top:1px solid #ddd;padding:22px 0 32px;display:flex;gap:20px;color:#777;font-size:11px}footer span{margin-right:auto}.consent{position:fixed;bottom:14px;left:50%;transform:translateX(-50%);width:min(760px,calc(100% - 24px));background:#fff;border:1px solid #ddd;padding:16px;border-radius:7px;display:flex;align-items:center;gap:18px;box-shadow:0 10px 35px #0002}.consent p,.muted{font-size:12px;line-height:1.6;color:#666}.consent form{display:flex;gap:8px;flex-shrink:0}button{border:0;border-radius:4px;padding:11px 15px;font-weight:700;cursor:pointer}.yes{background:#222;color:white}.no{background:#eee;color:#222}.page{padding:48px 0}.page h1{font-size:clamp(38px,8vw,64px);letter-spacing:-.05em}.card{max-width:650px;background:#fff;border:1px solid #ddd;border-radius:7px;padding:22px}.card input{width:100%;padding:12px;margin:8px 0 15px;background:#fafafa;color:#222;border:1px solid #ccc;border-radius:4px}.visitor{padding:14px;margin:9px 0;background:#fff;border:1px solid #ddd;border-radius:6px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}.visitor code{color:#333}.back{display:inline-block;margin:25px 0;color:#555}.location{font-size:12px;color:#666;margin-top:5px}@media(max-width:620px){.hero{min-height:430px}.below{display:block}.social{display:block;margin-top:20px}.consent{display:block}.consent form{margin-top:12px}.consent button{width:48%}}</style></head><body><div class="wrap">{{ body|safe }}</div></body></html>"""
@app.route("/")
def home():
    choice=request.cookies.get("visitor_analytics")
    body=r"""<div class="top">THUGORANGE7</div><section class="hero"><div class="eyebrow">TIKTOK CREATOR</div><h1>thug<span>orange</span><sup>7</sup></h1><div class="handle">@thugorange7</div><p class="intro">TikTok videos, updates and more.</p><a class="cta" href="https://www.tiktok.com/@thugorange7" target="_blank" rel="noopener">FOLLOW ON TIKTOK ↗</a><p class="eyebrow" style="margin-top:30px"></p></section>{% if choice == "yes" %}<section class="card" style="max-width:520px;margin:0 auto 55px"><b>Leave a name (optional)</b><p class="muted">Your name is shown only in the private owner dashboard and is stored with your opted-in visit record until that record is cleared.</p><form method="post" action="/visitor/name"><input type="hidden" name="csrf_token" value="{{ token }}"><input name="visitor_name" maxlength="40" required placeholder="Your name or nickname"><button class="yes">Save name</button></form></section>{% endif %}<section class="below"><div><div class="eyebrow">FIND ME</div><h2>See you on<br><span class="accent">TikTok.</span></h2></div><a class="social" href="https://www.tiktok.com/@thugorange7" target="_blank" rel="noopener"><b>♪ &nbsp; @thugorange7</b><small>Watch videos · Follow · Stay updated</small></a></section><footer><span>© thugorange7</span><a href="/privacy">PRIVACY</a><a href="/owner">OWNER</a></footer>{% if not choice %}<div class="consent"><div><b>Privacy choice</b><p>If you choose Allow, this site stores your IP address and visit time and uses ipwho.is to estimate your city, region and country from your IP address. Location can be inaccurate. Only the site owner can see these details. Records older than 7 days are cleared the next time the site or owner dashboard is accessed. If you allow, you can optionally leave a name; it is visible only to the site owner and is cleared with the visit record.</p></div><form method="post" action="/privacy/consent"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="yes" name="choice" value="yes">Allow</button><button class="no" name="choice" value="no">Decline</button></form></div>{% endif %}"""
    return render_template_string(BASE,body=render_template_string(body,choice=choice,token=generate_csrf()))
@app.route("/privacy")
def privacy():
    body=r"""<section class="page"><div class="eyebrow">PRIVACY</div><h1>Your data.<br><span class="accent">Your choice.</span></h1><div class="card"><p>If you choose Allow, your IP address and visit time are stored and an ipwho.is is used to estimate your city, region and country from your IP address. This location is approximate and may be wrong. Any name you submit is optional. Leaving a name is optional. The site owner can view the IP address, approximate city, region, country, optional name, and visit count in the private owner page. Records older than 7 days are cleared the next time the site or owner dashboard is accessed.</p><p>If you choose Decline, this site does not save your IP in its visitor analytics database. The hosting provider may still process connection data to operate the website.</p><form method="post" action="/privacy/consent"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="yes" name="choice" value="yes">Allow analytics</button> <button class="no" name="choice" value="no">Decline analytics</button></form></div><a class="back" href="/">← Back</a></section>"""
    return render_template_string(BASE,body=render_template_string(body,token=generate_csrf()))
@app.route("/privacy/consent",methods=["POST"])
def consent():
    c=request.form.get("choice")
    if c not in ("yes","no"): abort(400)
    r=redirect(url_for("home")); r.set_cookie("visitor_analytics",c,max_age=2592000,secure=app.config["SESSION_COOKIE_SECURE"],httponly=True,samesite="Lax"); return r
@app.route("/visitor/name",methods=["POST"])
def visitor_name():
    if request.cookies.get("visitor_analytics")!="yes": abort(403)
    name="".join(ch for ch in request.form.get("visitor_name","").strip() if ch.isprintable())[:40]
    if not name: abort(400)
    ip=(request.remote_addr or "")[:64]
    if not ip: abort(400)
    try:
        purge()
        v=Visitor.query.filter_by(ip_address=ip).first()
        if v: v.visitor_name=name; v.last_seen=now(); add_location(v)
        else:
            v=Visitor(ip_address=ip,visitor_name=name,last_seen=now(),visits=1); add_location(v); db.session.add(v)
        db.session.commit()
    except Exception:
        db.session.rollback(); abort(500)
    return redirect(url_for("home"))
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
    body=r"""<section class="page"><div class="eyebrow">PRIVATE DASHBOARD</div><h1>Visitor <span class="accent">stats.</span></h1><p class="muted">Only visitors who accepted analytics appear here. IP and approximate location records expire after 7 days. Location is estimated from IP and may be inaccurate or unavailable.</p><h2>{{ rows|length }} unique IPs</h2>{% for v in rows %}<div class="visitor"><div>{% if v.visitor_name %}<b>{{ v.visitor_name }}</b><br>{% endif %}<code>{{ v.ip_address }}</code><div class="location">{{ v.city or 'Location unavailable' }}{% if v.region %}, {{ v.region }}{% endif %}{% if v.country %}, {{ v.country }}{% endif %}</div></div><span>{{ v.visits }} visits · {{ v.last_seen.strftime('%d %b %Y %H:%M UTC') }}</span></div>{% else %}<p class="muted">No opt-in visitors yet.</p>{% endfor %}<form method="post" action="/owner/logout"><input type="hidden" name="csrf_token" value="{{ token }}"><button class="no">Log out</button></form><a class="back" href="/">← View site</a></section>"""
    return render_template_string(BASE,body=render_template_string(body,rows=rows,token=generate_csrf()))
@app.route("/owner/logout",methods=["POST"])
def logout():
    if session.get("creator_owner") is not True: abort(403)
    session.pop("creator_owner",None); return redirect(url_for("home"))
