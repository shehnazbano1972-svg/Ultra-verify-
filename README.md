# Naxora Verify Website

Handles Discord OAuth2 verification. Stores `user_id + access_token + refresh_token` so the bot's `!join` command can add verified users to servers.

## How It Works

```
Discord #verify channel
      │
      ▼
User clicks [Verify Now] button
      │  (button links to https://your-site.com/authorize?guild=GUILD_ID)
      ▼
Discord OAuth page — scopes: identify  guilds.join
      │
      ▼
User clicks Authorize
      │
      ▼
Discord redirects to DISCORD_REDIRECT_URI  (your /callback URL)
      │
      ▼
Website exchanges code → gets access_token + refresh_token
Stores: user_id, access_token, refresh_token in database
      │
      ▼
Shows "Verification Successful" page
      │
Later...
      ▼
Bot runs !join 10
Reads 10 tokens from DB → calls Discord guilds.join API → adds users
```

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env — fill in DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI
python app.py
```

## Discord App Setup

1. Go to https://discord.com/developers/applications
2. Select your app → **OAuth2 → General**
3. Under **Redirects**, click **Add Redirect** and paste your callback URL:
   - Local:   `http://localhost:5000/callback`
   - Railway: `https://your-app.railway.app/callback`
4. Save changes
5. Copy **Client ID** and **Client Secret** into your `.env`

## Verify Button URL (for the bot's embed)

The button in Discord's `#verify` channel should link to:
```
https://your-site.com/authorize?guild=GUILD_ID
```

The bot's `!verify setup` command builds this URL automatically using `VERIFY_WEBSITE_URL`.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DISCORD_CLIENT_ID` | ✅ | Your app's client ID |
| `DISCORD_CLIENT_SECRET` | ✅ | Your app's client secret |
| `DISCORD_REDIRECT_URI` | ✅ | Exact callback URL (must match Discord dev portal) |
| `FLASK_SECRET_KEY` | ✅ | Random string for Flask sessions |
| `VERIFY_SECRET` | ✅ | Shared secret with the bot |
| `BOT_TOKEN` | ❌ | Bot token — if set, assigns Verified role immediately on auth |
| `VERIFIED_ROLE_ID` | ❌ | Role ID to assign on auth (requires BOT_TOKEN) |
| `DB_PATH` | ❌ | SQLite DB path (default: `db/memberstock.db`) |
| `PORT` | ❌ | Port to bind (default: 5000) |

## Bot API Endpoints

All require header: `Authorization: Bearer <VERIFY_SECRET>`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/stock` | List all stored tokens |
| `GET` | `/api/stock?limit=10&offset=0` | Paginated |
| `GET` | `/api/count` | Total count |
| `DELETE` | `/api/stock/<user_id>` | Remove a user |
| `GET` | `/health` | Health check + total count |

## Deploy on Railway

1. Push to GitHub
2. Connect repo on Railway → **New Project → Deploy from GitHub**
3. Add env vars in Railway dashboard
4. Railway sets `PORT` automatically — no changes needed

## Deploy on Render

1. Connect repo → **New Web Service**
2. Build: `pip install -r requirements.txt`
3. Start: `python app.py`
4. Add env vars

## Deploy with Docker

```bash
docker build -t naxora-verify .
docker run -p 5000:5000 --env-file .env naxora-verify
```
