# 🚀 Deploy Zero Trust Security App to Cloudflare

This guide shows how to deploy the app using **Cloudflare Tunnel** so anyone on the internet can access it via a public URL — no port forwarding needed.

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Node.js ≥ 18 | `node --version` |
| npm | `npm --version` |
| Cloudflare account | [Sign up free](https://dash.cloudflare.com/sign-up) |
| cloudflared CLI | See Step 1 below |
| Supabase project | Already configured in `.env` |

---

## Step 1 — Install `cloudflared` CLI

### macOS (Homebrew)
```bash
brew install cloudflared
```

### Windows
```bash
winget install Cloudflare.cloudflared
```

### Linux (Debian/Ubuntu)
```bash
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared
```

### Verify installation
```bash
cloudflared --version
```

---

## Step 2 — Install Dependencies & Set Up `.env`

```bash
cd "/Users/rajan/UWS Dessertation/Zero trust security"
npm install
```

Make sure your `.env` file exists with these values:
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-service-role-key
PORT=3000
```

---

## Step 3 — Start the App Locally

```bash
npm start
```

You should see:
```
Server running on http://localhost:3000
✓ Database schema OK (phone, gender columns exist)
```

Open http://localhost:3000 in your browser to confirm it works.

---

## Step 4 — Option A: Quick Tunnel (No Account Needed)

This creates a **temporary public URL** — perfect for demos and testing.

Open a **second terminal** and run:

```bash
cloudflared tunnel --url http://localhost:3000
```

After a few seconds, you'll see output like:
```
+--------------------------------------------------------------------------------------------+
|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
|  https://random-words-here.trycloudflare.com                                               |
+--------------------------------------------------------------------------------------------+
```

✅ **That URL is your live deployed app!** Share it with anyone.

> ⚠️ This URL changes every time you restart cloudflared. For a permanent URL, see Option B.

---

## Step 4 — Option B: Named Tunnel with Custom Domain (Permanent)

### 4B.1 — Log in to Cloudflare

```bash
cloudflared login
```

This opens your browser. Select the domain you want to use and authorize.

### 4B.2 — Create a Named Tunnel

```bash
cloudflared tunnel create zero-trust-demo
```

This creates a tunnel and outputs a **Tunnel ID** (e.g., `a1b2c3d4-...`). Note it down.

It also creates a credentials file at:
```
~/.cloudflared/<TUNNEL-ID>.json
```

### 4B.3 — Configure the Tunnel

Create a config file:

```bash
nano ~/.cloudflared/config.yml
```

Paste this (replace the values):

```yaml
tunnel: <YOUR-TUNNEL-ID>
credentials-file: /Users/rajan/.cloudflared/<YOUR-TUNNEL-ID>.json

ingress:
  - hostname: zerotrust.yourdomain.com
    service: http://localhost:3000
  - service: http_status:404
```

### 4B.4 — Add DNS Record

```bash
cloudflared tunnel route dns zero-trust-demo zerotrust.yourdomain.com
```

This creates a CNAME record in Cloudflare DNS automatically.

### 4B.5 — Run the Tunnel

```bash
cloudflared tunnel run zero-trust-demo
```

✅ Your app is now live at `https://zerotrust.yourdomain.com`

---

## Step 5 — Run Both Together (One Command)

You can start the server and tunnel together. Add this to `package.json` scripts:

```json
"tunnel": "cloudflared tunnel --url http://localhost:3000",
"deploy": "npm start & sleep 2 && npm run tunnel"
```

Then just run:
```bash
npm run deploy
```

---

## Step 6 — Keep It Running (Optional - Background Service)

### macOS (launchd)
```bash
cloudflared service install
brew services start cloudflared
```

### Linux (systemd)
```bash
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

---

## Architecture

```
┌──────────┐     HTTPS      ┌────────────────┐     HTTP      ┌──────────────┐
│  Browser  │ ───────────── │  Cloudflare     │ ──────────── │  Your Mac    │
│  (User)   │               │  Edge Network   │              │  localhost   │
│           │               │  (DDoS + SSL)   │              │  :3000       │
└──────────┘               └────────────────┘              └──────────────┘
                                                                    │
                                                                    ▼
                                                            ┌──────────────┐
                                                            │  Supabase    │
                                                            │  (Database)  │
                                                            └──────────────┘
```

**Benefits:**
- ✅ Free SSL/HTTPS (automatic)
- ✅ DDoS protection
- ✅ No port forwarding needed
- ✅ No static IP needed
- ✅ Works behind NAT/firewalls
- ✅ Zero Trust access controls available

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `cloudflared: command not found` | Reinstall: `brew install cloudflared` |
| Tunnel URL not loading | Make sure `npm start` is running on port 3000 first |
| `ERR_CONNECTION_REFUSED` | Check `.env` has correct `PORT=3000` |
| Profile save fails | Run `migrate.sql` in Supabase SQL Editor |
| Tunnel stops when terminal closes | Use `cloudflared service install` for background running |

---

## Quick Reference

| Command | What it does |
|---------|-------------|
| `npm start` | Start the app on localhost:3000 |
| `npm run start:dev` | Start with auto-reload (development) |
| `cloudflared tunnel --url http://localhost:3000` | Quick public URL (temporary) |
| `cloudflared tunnel run zero-trust-demo` | Named tunnel (permanent domain) |
| `npm run deploy` | Start app + tunnel together |
