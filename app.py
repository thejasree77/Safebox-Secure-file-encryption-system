import os, io, re, uuid, sqlite3, hashlib, secrets, zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from markupsafe import Markup
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file, g, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag
import crypto_utils as cu

BASE = os.path.dirname(os.path.abspath(__file__))
STORAGE = os.path.join(BASE, "storage")
DB = os.path.join(BASE, "database.db")
os.makedirs(STORAGE, exist_ok=True)

IST = timezone(timedelta(hours=5, minutes=30), "IST")
PASSWORD_METHOD = "pbkdf2:sha256:600000"
MAX_ATTEMPTS = 5

def load_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()

app = Flask(__name__)
app.secret_key = load_secret()
app.config.update(MAX_CONTENT_LENGTH=25 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("PRODUCTION")))
KEYS = {}   # session token -> unlocked RSA private key (memory only, never saved)

# ---------------- Time (stored as UTC, shown as IST) ----------------
def now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def parse(s):
    return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if s else None

@app.template_filter("ist")
def ist_filter(s, fmt="%d %b %Y, %I:%M %p"):
    d = parse(s)
    return d.astimezone(IST).strftime(fmt) + " IST" if d else "-"

@app.template_filter("remaining")
def remaining(s):
    secs = int((parse(s) - now()).total_seconds())
    if secs <= 0:
        return "Expired"
    days, rest = divmod(secs, 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days}d {hours}h" if days else f"{hours}h {rest // 60}m"

@app.template_filter("size")
def human_size(n):
    if n < 1024: return f"{n} B"
    if n < 1024 ** 2: return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.1f} MB"

EVENT_LABELS = {
    "LOGIN": "Signed in", "LOGIN_FAILED": "Wrong password at sign in",
    "UPLOAD": "File locked", "DOWNLOAD": "File unlocked",
    "SHARE": "Shared with a user", "REVOKE": "User access removed",
    "DELETE": "File deleted", "LINK_CREATED": "Share link created",
    "LINK_REVOKED": "Share link turned off", "LINK_DOWNLOAD": "Downloaded with a share link",
    "LINK_WRONG_PW": "Wrong link password", "LINK_LOCKED": "Link locked after wrong tries",
    "TAMPER": "File was changed", "WRONG_SECRET": "Wrong file password",
    "DENIED": "Access denied", "DESTROYED": "File deleted automatically",
    "PASSWORD_CHANGED": "Account password changed",
}

@app.template_filter("label")
def event_label(action):
    return EVENT_LABELS.get(action, action.title())

STATUS_LABELS = {"VERIFIED": "Safe", "TAMPERED": "Changed", "MISSING": "Missing"}

@app.template_filter("nice")
def nice_status(s):
    return STATUS_LABELS.get(s, s.title())

# ---------------- Database ----------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        public_key BLOB NOT NULL, encrypted_private_key BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL, owner_id INTEGER NOT NULL, stored_name TEXT NOT NULL,
        sha256 TEXT NOT NULL, size INTEGER NOT NULL, salt BLOB NOT NULL,
        cipher_sha256 TEXT NOT NULL DEFAULT '', strong INTEGER NOT NULL DEFAULT 1,
        owner_wrapped BLOB,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS file_keys (file_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        wrapped_key BLOB NOT NULL, PRIMARY KEY (file_id, user_id));
    CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, action TEXT, detail TEXT,
        severity TEXT NOT NULL DEFAULT 'normal', ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS shares (id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL, file_id INTEGER NOT NULL, owner_id INTEGER NOT NULL,
        locked_key BLOB NOT NULL, salt BLOB NOT NULL, expires_at TEXT NOT NULL,
        max_downloads INTEGER NOT NULL, downloads INTEGER NOT NULL DEFAULT 0,
        destroy_on_expiry INTEGER NOT NULL DEFAULT 0, destroy_on_first INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT);
    CREATE TABLE IF NOT EXISTS share_items (share_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
        locked_key BLOB NOT NULL, PRIMARY KEY (share_id, file_id));
    """)
    def add_column(table, col, ddl):
        have = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
        if col not in have:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    add_column("files", "cipher_sha256", "TEXT NOT NULL DEFAULT ''")
    add_column("files", "strong", "INTEGER NOT NULL DEFAULT 1")
    add_column("files", "owner_wrapped", "BLOB")
    add_column("logs", "severity", "TEXT NOT NULL DEFAULT 'normal'")
    for fid, name in db.execute("SELECT id, stored_name FROM files WHERE cipher_sha256=''").fetchall():
        try:
            db.execute("UPDATE files SET cipher_sha256=? WHERE id=?",
                       (sha256_file(os.path.join(STORAGE, name)), fid))
        except FileNotFoundError:
            pass
    # old single-file links become links with one file
    db.execute("""INSERT INTO share_items (share_id, file_id, locked_key)
        SELECT id, file_id, locked_key FROM shares
        WHERE id NOT IN (SELECT share_id FROM share_items)""")
    db.commit()
    db.close()

def log(action, detail="", sev="normal", uid=None):
    """Security event. Never put passwords or file contents in `detail`."""
    db = get_db()
    db.execute("INSERT INTO logs (user_id, action, detail, severity, ts) VALUES (?,?,?,?,?)",
               (uid if uid is not None else session.get("user_id"), action, detail, sev, iso(now())))
    db.commit()

# ---------------- Request guards ----------------
@app.context_processor
def inject_csrf():
    def csrf_field():
        session.setdefault("csrf", secrets.token_hex(16))
        return Markup(f'<input type="hidden" name="csrf" value="{session["csrf"]}">')
    session.setdefault("csrf", secrets.token_hex(16))
    return {"csrf": session["csrf"], "csrf_field": csrf_field}

@app.before_request
def before():
    if request.endpoint == "static":
        return
    if request.method == "POST":
        tok = session.get("csrf")
        if not tok or not secrets.compare_digest(request.form.get("csrf", ""), tok):
            abort(400)
    sweep()

def login_required(view):
    @wraps(view)
    def wrapped(*a, **k):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("tok") not in KEYS:
            session.clear()
            flash("Your session ended. Please sign in again.", "warn")
            return redirect(url_for("login"))
        return view(*a, **k)
    return wrapped

def my_priv():
    return KEYS[session["tok"]]

def my_public():
    r = get_db().execute("SELECT public_key FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return cu.load_public_key(r["public_key"])

# ---------------- Helpers ----------------
def is_strong(s):
    kinds = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return len(s) >= 12 and kinds >= 3

def file_status(row):
    try:
        ok = sha256_file(os.path.join(STORAGE, row["stored_name"])) == row["cipher_sha256"]
    except FileNotFoundError:
        return "MISSING"
    return "VERIFIED" if ok else "TAMPERED"

def my_files():
    rows = get_db().execute("""SELECT f.*, u.username AS owner FROM files f
        JOIN file_keys k ON k.file_id=f.id JOIN users u ON u.id=f.owner_id
        WHERE k.user_id=? ORDER BY f.id DESC""", (session["user_id"],)).fetchall()
    return [dict(r, status=file_status(r)) for r in rows]

def access_row(fid):
    return get_db().execute("""SELECT f.*, k.wrapped_key, u.username AS owner FROM files f
        JOIN file_keys k ON k.file_id=f.id JOIN users u ON u.id=f.owner_id
        WHERE f.id=? AND k.user_id=?""", (fid, session["user_id"])).fetchone()

def owner_row(fid):
    row = access_row(fid)
    if not row or row["owner_id"] != session["user_id"]:
        log("DENIED", f"file {fid}", "warning")
        abort(403)
    return row

def share_state(s):
    if s["revoked"]:
        return "Locked" if s["attempts"] >= MAX_ATTEMPTS else "Revoked"
    if parse(s["expires_at"]) <= now():
        return "Expired"
    if s["downloads"] >= s["max_downloads"]:
        return "Limit reached"
    return "Active"

def link_files(sid):
    return get_db().execute("""SELECT f.id, f.filename, f.size FROM share_items i
        JOIN files f ON f.id=i.file_id WHERE i.share_id=? ORDER BY f.filename""", (sid,)).fetchall()

def destroy_file(fid, action="DESTROYED", sev="warning", note=""):
    """Remove the encrypted file, its keys and its links from the server."""
    db = get_db()
    row = db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not row:
        return
    try:
        os.remove(os.path.join(STORAGE, row["stored_name"]))
    except FileNotFoundError:
        pass
    for table in ("file_keys", "share_items"):
        db.execute(f"DELETE FROM {table} WHERE file_id=?", (fid,))
    db.execute("DELETE FROM shares WHERE id NOT IN (SELECT share_id FROM share_items)")
    db.execute("DELETE FROM files WHERE id=?", (fid,))
    db.commit()
    log(action, f"{row['filename']} {note}".strip(), sev, uid=row["owner_id"])

def sweep():
    rows = get_db().execute("""SELECT DISTINCT i.file_id FROM share_items i
        JOIN shares s ON s.id=i.share_id
        WHERE s.destroy_on_expiry=1 AND s.revoked=0 AND s.expires_at<=?""", (iso(now()),)).fetchall()
    for r in rows:
        destroy_file(r["file_id"], note="(link expired)")

def advisor(uid, files):
    mine = [f for f in files if f["owner_id"] == uid]
    ever = get_db().execute("SELECT COUNT(*) FROM shares WHERE owner_id=?", (uid,)).fetchone()[0]
    checks = [
        (True, "Files are locked with strong encryption", "", 40),
        (all(f["strong"] for f in mine), "Strong passwords",
         "Use longer passwords: 12+ characters with letters, numbers and symbols", 25),
        (all(f["status"] == "VERIFIED" for f in mine), "No file has been changed",
         "A file was changed or is missing. Check My Files", 25),
        (ever > 0 or not mine, "Safe sharing is set up",
         "Try sharing a file with a protected link", 10),
    ]
    return sum(c[3] for c in checks if c[0]), checks

# ---------------- Auth ----------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        if len(u) < 3 or len(p) < 8:
            flash("Username needs 3+ characters and password needs 8+.", "err")
            return redirect(url_for("register"))
        if p != request.form.get("confirm", ""):
            flash("The two passwords do not match.", "err")
            return redirect(url_for("register"))
        priv, pub = cu.generate_rsa_keypair()
        try:
            get_db().execute(
                "INSERT INTO users (username,password_hash,public_key,encrypted_private_key) VALUES (?,?,?,?)",
                (u, generate_password_hash(p, method=PASSWORD_METHOD),
                 cu.public_key_to_pem(pub), cu.private_key_to_encrypted_pem(priv, p)))
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("That username is taken. Try another.", "err")
            return redirect(url_for("register"))
        flash("Account created. You can sign in now.", "ok")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE username=?",
                                (request.form["username"].strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"], pw):
            tok = uuid.uuid4().hex
            KEYS[tok] = cu.load_private_key(user["encrypted_private_key"], pw)
            session.clear()
            session.update(user_id=user["id"], username=user["username"], tok=tok)
            log("LOGIN")
            return redirect(url_for("dashboard"))
        if user:
            log("LOGIN_FAILED", "", "warning", uid=user["id"])
        flash("Wrong username or password.", "err")
    return render_template("login.html")

@app.route("/logout")
def logout():
    KEYS.pop(session.get("tok"), None)
    session.clear()
    return redirect(url_for("login"))

# ---------------- Home ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    db, uid = get_db(), session["user_id"]
    files = my_files()
    mine = [f for f in files if f["owner_id"] == uid]
    links = db.execute("SELECT * FROM shares WHERE owner_id=?", (uid,)).fetchall()
    score, checks = advisor(uid, files)
    events = db.execute("SELECT * FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 5", (uid,)).fetchall()
    return render_template("dashboard.html", encrypted=len(mine), received=len(files) - len(mine),
        active_links=sum(1 for l in links if share_state(l) == "Active"),
        score=score, checks=checks, events=events,
        alert=any(f["status"] != "VERIFIED" for f in mine))

# ---------------- Lock a file ----------------
@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt():
    if request.method == "GET":
        return render_template("encrypt.html")
    f, secret = request.files.get("file"), request.form.get("secret", "")
    if not f or not f.filename or len(secret) < 8:
        flash("Choose a file and a password of at least 8 characters.", "err")
        return redirect(url_for("encrypt"))
    data = f.read()
    if not data:
        flash("That file is empty.", "err")
        return redirect(url_for("encrypt"))
    aes_key, blob = cu.encrypt_bytes(data)
    salt, stored = os.urandom(16), uuid.uuid4().hex + ".enc"
    with open(os.path.join(STORAGE, stored), "wb") as out:
        out.write(blob)
    db = get_db()
    fid = db.execute("""INSERT INTO files (filename,owner_id,stored_name,sha256,size,salt,cipher_sha256,strong,uploaded_at,owner_wrapped)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (secure_filename(f.filename) or "file", session["user_id"], stored,
         hashlib.sha256(data).hexdigest(), len(data), salt,
         hashlib.sha256(blob).hexdigest(), int(is_strong(secret)), iso(now()),
         cu.wrap_key(aes_key, my_public()))).lastrowid       # owner copy: lets you make share links without retyping
    inner = cu.lock_key(aes_key, secret, salt)               # lock 1: file password
    names = {session["username"]} | {n.strip() for n in request.form.get("recipients", "").split(",") if n.strip()}
    for n in names:
        u = db.execute("SELECT id, public_key FROM users WHERE username=?", (n,)).fetchone()
        if not u:
            flash(f"User '{n}' was not found, so the file was not shared with them.", "warn")
            continue
        db.execute("INSERT OR IGNORE INTO file_keys VALUES (?,?,?)",
                   (fid, u["id"], cu.wrap_key(inner, cu.load_public_key(u["public_key"]))))  # lock 2: RSA
    db.commit()
    log("UPLOAD", f.filename)
    flash("File locked and saved. Keep your password safe: SafeBox does not keep a copy.", "ok")
    return redirect(url_for("file_detail", fid=fid))

# ---------------- Unlock a file ----------------
@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt():
    if request.method == "GET":
        return render_template("decrypt.html", files=my_files(), selected=request.args.get("file", type=int))
    fid, secret = request.form.get("file_id", type=int), request.form.get("secret", "")
    row = access_row(fid) if fid else None
    if not row:
        log("DENIED", f"file {fid}", "warning")
        abort(403)
    if file_status(row) != "VERIFIED":
        log("TAMPER", row["filename"], "threat")
        return render_template("tamper.html", f=row, status=file_status(row)), 409
    try:
        inner = cu.unwrap_key(row["wrapped_key"], my_priv())
        aes_key = cu.unlock_key(inner, secret, row["salt"])
    except (InvalidTag, ValueError):
        log("WRONG_SECRET", row["filename"], "warning")
        flash("That password is not correct. Check it and try again.", "err")
        return redirect(url_for("decrypt", file=fid))
    with open(os.path.join(STORAGE, row["stored_name"]), "rb") as fh:
        blob = fh.read()
    try:
        data = cu.decrypt_bytes(aes_key, blob)
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise InvalidTag()
    except InvalidTag:
        log("TAMPER", row["filename"], "threat")
        return render_template("tamper.html", f=row, status="TAMPERED"), 409
    log("DOWNLOAD", row["filename"])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=row["filename"])

# ---------------- My Files ----------------
@app.route("/files")
@login_required
def files():
    rows = my_files()
    return render_template("files.html", files=rows, alert=any(f["status"] != "VERIFIED" for f in rows),
                           bad=[f for f in rows if f["status"] != "VERIFIED"])

@app.route("/file/<int:fid>")
@login_required
def file_detail(fid):
    row = access_row(fid)
    if not row:
        log("DENIED", f"file {fid}", "warning")
        abort(403)
    db, uid = get_db(), session["user_id"]
    is_owner = row["owner_id"] == uid
    people = db.execute("""SELECT u.id, u.username FROM file_keys k JOIN users u ON u.id=k.user_id
        WHERE k.file_id=? AND k.user_id!=?""", (fid, row["owner_id"])).fetchall() if is_owner else []
    links = [l for l in db.execute("""SELECT s.* FROM shares s JOIN share_items i ON i.share_id=s.id
        WHERE i.file_id=?""", (fid,)).fetchall() if share_state(l) == "Active"] if is_owner else []
    status = file_status(row)
    return render_template("file.html", f=row, status=status, is_owner=is_owner, people=people,
                           links=len(links), alert=status != "VERIFIED")

@app.route("/file/<int:fid>/share", methods=["POST"])
@login_required
def share_user(fid):
    row, db = owner_row(fid), get_db()
    name = request.form.get("recipient", "").strip()
    u = db.execute("SELECT id, public_key FROM users WHERE username=?", (name,)).fetchone()
    if not u:
        flash("No user with that name.", "err")
        return redirect(url_for("file_detail", fid=fid))
    inner = cu.unwrap_key(row["wrapped_key"], my_priv())
    db.execute("INSERT OR IGNORE INTO file_keys VALUES (?,?,?)",
               (fid, u["id"], cu.wrap_key(inner, cu.load_public_key(u["public_key"]))))
    db.commit()
    log("SHARE", f"{row['filename']} to {name}")
    flash(f"Shared with {name}. Send them the file password privately.", "ok")
    return redirect(url_for("file_detail", fid=fid))

@app.route("/file/<int:fid>/revoke/<int:uid>", methods=["POST"])
@login_required
def revoke_user(fid, uid):
    row = owner_row(fid)
    if uid != session["user_id"]:
        get_db().execute("DELETE FROM file_keys WHERE file_id=? AND user_id=?", (fid, uid))
        get_db().commit()
        log("REVOKE", row["filename"])
        flash("Access removed.", "ok")
    return redirect(url_for("file_detail", fid=fid))

@app.route("/file/<int:fid>/delete", methods=["POST"])
@login_required
def delete_file(fid):
    owner_row(fid)
    destroy_file(fid, action="DELETE", sev="normal")
    flash("File deleted.", "ok")
    return redirect(url_for("files"))

# ---------------- Share Links ----------------
EXPIRY = {1: "1 hour", 24: "24 hours", 168: "7 days", 720: "30 days"}

@app.route("/secure-share")
@login_required
def secure_share():
    uid = session["user_id"]
    mine = [f for f in my_files() if f["owner_id"] == uid]
    rows = get_db().execute("SELECT * FROM shares WHERE owner_id=? ORDER BY id DESC", (uid,)).fetchall()
    links = [dict(r, state=share_state(r), files=link_files(r["id"]),
                  url=url_for("public_share", token=r["token"], _external=True)) for r in rows]
    new = next((l for l in links if l["id"] == request.args.get("new", type=int)), None)
    return render_template("share.html", files=mine, links=links, new=new,
                           selected=request.args.get("file", type=int), expiry=EXPIRY)

@app.route("/secure-share/create", methods=["POST"])
@login_required
def create_link():
    ids = list(dict.fromkeys(request.form.getlist("file_ids", type=int)))
    if not ids:
        flash("Tick at least one file to share.", "err")
        return redirect(url_for("secure_share"))
    hours = request.form.get("expiry", type=int)
    hours = hours if hours in EXPIRY else 24
    limit = min(max(request.form.get("limit", 3, type=int), 1), 50)
    link_pw = request.form.get("link_password", "")
    if len(link_pw) < 6:
        flash("The link password needs at least 6 characters.", "err")
        return redirect(url_for("secure_share"))
    salt = os.urandom(16)
    db, items, names = get_db(), [], []
    for fid in ids:
        row = owner_row(fid)
        if row["owner_wrapped"]:
            aes_key = cu.unwrap_key(row["owner_wrapped"], my_priv())
        else:                                   # older file: ask for its password once
            try:
                inner = cu.unwrap_key(row["wrapped_key"], my_priv())
                aes_key = cu.unlock_key(inner, request.form.get(f"pw_{fid}", ""), row["salt"])
            except (InvalidTag, ValueError):
                log("WRONG_SECRET", row["filename"], "warning")
                flash(f"The password for '{row['filename']}' is not correct. No link was made.", "err")
                return redirect(url_for("secure_share", file=fid))
            db.execute("UPDATE files SET owner_wrapped=? WHERE id=?",
                       (cu.wrap_key(aes_key, my_public()), fid))
        items.append((fid, cu.lock_key(aes_key, link_pw, salt)))
        names.append(row["filename"])
    sid = db.execute("""INSERT INTO shares (token,file_id,owner_id,locked_key,salt,expires_at,max_downloads,
        destroy_on_expiry,destroy_on_first,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (secrets.token_urlsafe(8), items[0][0], session["user_id"], items[0][1], salt,
         iso(now() + timedelta(hours=hours)), limit,
         int(bool(request.form.get("destroy_expiry"))), int(bool(request.form.get("destroy_first"))),
         iso(now()))).lastrowid
    db.executemany("INSERT INTO share_items (share_id,file_id,locked_key) VALUES (?,?,?)",
                   [(sid, f, k) for f, k in items])
    db.commit()
    log("LINK_CREATED", f"{', '.join(names)}; ends in {EXPIRY[hours]}")
    flash("Share link created. Send the link and its password in different messages.", "ok")
    return redirect(url_for("secure_share", new=sid))

@app.route("/secure-share/<int:sid>/revoke", methods=["POST"])
@login_required
def revoke_link(sid):
    s = get_db().execute("SELECT * FROM shares WHERE id=?", (sid,)).fetchone()
    if not s or s["owner_id"] != session["user_id"]:
        abort(403)
    get_db().execute("UPDATE shares SET revoked=1 WHERE id=?", (sid,))
    get_db().commit()
    log("LINK_REVOKED", ", ".join(f["filename"] for f in link_files(sid)))
    flash("Link turned off. It no longer works.", "ok")
    return redirect(url_for("secure_share"))

@app.route("/s/<token>", methods=["GET", "POST"])
def public_share(token):
    """Public page: no login, but the link password is required."""
    db = get_db()
    s = db.execute("SELECT * FROM shares WHERE token=?", (token,)).fetchone()
    if not s:
        return render_template("public_share.html", s=None, items=[], state="Invalid"), 404
    items = db.execute("""SELECT i.file_id, i.locked_key, f.filename, f.size, f.stored_name, f.sha256, f.cipher_sha256
        FROM share_items i JOIN files f ON f.id=i.file_id WHERE i.share_id=? ORDER BY f.filename""",
        (s["id"],)).fetchall()
    state = share_state(s)
    if request.method == "GET" or state != "Active":
        return render_template("public_share.html", s=s, items=items, state=state)
    pick = request.form.get("pick", "all")
    chosen = list(items) if pick == "all" else [i for i in items if str(i["file_id"]) == pick]
    if not chosen:
        abort(400)
    names = ", ".join(i["filename"] for i in chosen)
    try:
        keys = {i["file_id"]: cu.unlock_key(i["locked_key"], request.form.get("password", ""), s["salt"])
                for i in chosen}
    except InvalidTag:
        attempts = s["attempts"] + 1
        locked = attempts >= MAX_ATTEMPTS
        db.execute("UPDATE shares SET attempts=?, revoked=? WHERE id=?", (attempts, int(locked), s["id"]))
        db.commit()
        log("LINK_LOCKED" if locked else "LINK_WRONG_PW", names, "warning", uid=s["owner_id"])
        flash("Wrong password. This link locks after 5 wrong tries." if not locked
              else "Too many wrong tries. This link is now locked.", "err")
        return render_template("public_share.html", s=s, items=items,
                               state=share_state(dict(s, revoked=int(locked), attempts=attempts)))
    out = []
    try:
        for i in chosen:
            path = os.path.join(STORAGE, i["stored_name"])
            if sha256_file(path) != i["cipher_sha256"]:
                raise InvalidTag()
            with open(path, "rb") as fh:
                data = cu.decrypt_bytes(keys[i["file_id"]], fh.read())
            if hashlib.sha256(data).hexdigest() != i["sha256"]:
                raise InvalidTag()
            out.append((i, data))
    except (InvalidTag, FileNotFoundError):
        log("TAMPER", names, "threat", uid=s["owner_id"])
        return render_template("public_share.html", s=s, items=items, state="Blocked"), 409
    db.execute("UPDATE shares SET downloads=downloads+1 WHERE id=?", (s["id"],))
    db.commit()
    log("LINK_DOWNLOAD", names, uid=s["owner_id"])
    if s["destroy_on_first"]:
        for i, _ in out:
            destroy_file(i["file_id"], note="(after first download)")
    if len(out) == 1:
        return send_file(io.BytesIO(out[0][1]), as_attachment=True, download_name=out[0][0]["filename"])
    buf, used = io.BytesIO(), set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, (i, data) in enumerate(out, 1):
            name = i["filename"] if i["filename"] not in used else f"{n}_{i['filename']}"
            used.add(name)
            z.writestr(name, data)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="safebox-files.zip")

# ---------------- Activity & settings ----------------
@app.route("/events")
@login_required
def events():
    rows = get_db().execute("SELECT * FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 100",
                            (session["user_id"],)).fetchall()
    return render_template("events.html", events=rows)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        old, new = request.form.get("old", ""), request.form.get("new", "")
        if not check_password_hash(user["password_hash"], old):
            flash("Current password is not correct.", "err")
        elif len(new) < 8 or new != request.form.get("confirm", ""):
            flash("New password needs 8+ characters and both entries must match.", "err")
        else:
            db.execute("UPDATE users SET password_hash=?, encrypted_private_key=? WHERE id=?",
                       (generate_password_hash(new, method=PASSWORD_METHOD),
                        cu.private_key_to_encrypted_pem(my_priv(), new), user["id"]))
            db.commit()
            log("PASSWORD_CHANGED")
            flash("Password changed.", "ok")
        return redirect(url_for("settings"))
    return render_template("settings.html")

init_db()

if __name__ == "__main__":
    app.run(debug=not os.environ.get("PRODUCTION"))