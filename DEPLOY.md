# 🚀 Deploy Zero Trust Security App — IONOS VPS# 🚀 Deploy Zero Trust Security App to Cloudflare



Complete step-by-step guide to deploy this app permanently on an **IONOS VPS** server.This guide shows how to deploy the app using **Cloudflare Tunnel** so anyone on the internet can access it via a public URL — no port forwarding needed.



**Cost: ~£2/month** (VPS only — Supabase database is free)---



---## Prerequisites



## Step 1 — Buy an IONOS VPS| Requirement | Check |

|-------------|-------|

1. Go to [https://www.ionos.co.uk/servers/vps](https://www.ionos.co.uk/servers/vps)| Node.js ≥ 18 | `node --version` |

2. Choose **VPS Linux S** (£2/mo) or **VPS Linux M** (£4/mo)| npm | `npm --version` |

3. Select **Ubuntu 22.04** as the operating system| Cloudflare account | [Sign up free](https://dash.cloudflare.com/sign-up) |

4. Complete the purchase| cloudflared CLI | See Step 1 below |

5. IONOS will email you:| Supabase project | Already configured in `.env` |

   - **Server IP address** (e.g. `85.215.xxx.xxx`)

   - **Root password**---



---## Step 1 — Install `cloudflared` CLI



## Step 2 — Connect to Your VPS via SSH### macOS (Homebrew)

```bash

Open **Terminal** on your Mac and run:brew install cloudflared

```

```bash

ssh root@YOUR_SERVER_IP### Windows

``````bash

winget install Cloudflare.cloudflared

Type `yes` when asked about fingerprint, then enter the root password from the email.```



You are now inside your IONOS VPS server! 🎉### Linux (Debian/Ubuntu)

```bash

---curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list

## Step 3 — Install Node.js, Git, Nginx on the VPSsudo apt update && sudo apt install cloudflared

```

Run these commands one by one on the VPS:

### Verify installation

```bash```bash

# Update the systemcloudflared --version

sudo apt update && sudo apt upgrade -y```



# Install Node.js 20---

curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

sudo apt install -y nodejs## Step 2 — Install Dependencies & Set Up `.env`



# Install Git and Nginx```bash

sudo apt install -y git nginxcd "/Users/rajan/UWS Dessertation/Zero trust security"

npm install

# Install PM2 (keeps your app running 24/7)```

sudo npm install -g pm2

```Make sure your `.env` file exists with these values:

```

Verify everything installed:SUPABASE_URL=https://your-project.supabase.co

SUPABASE_KEY=your-service-role-key

```bashPORT=3000

node --version    # should show v20.x.x```

npm --version     # should show 10.x.x

git --version     # should show git version 2.x.x---

nginx -v          # should show nginx/1.x.x

pm2 --version     # should show 5.x.x## Step 3 — Start the App Locally

```

```bash

---npm start

```

## Step 4 — Clone Your App from GitHub

You should see:

```bash```

cd /var/wwwServer running on http://localhost:3000

git clone https://github.com/rajanchand/Zero-trust-security-demo.git✓ Database schema OK (phone, gender columns exist)

cd Zero-trust-security-demo```

npm install

```Open http://localhost:3000 in your browser to confirm it works.



------



## Step 5 — Create the `.env` File## Step 4 — Option A: Quick Tunnel (No Account Needed)



```bashThis creates a **temporary public URL** — perfect for demos and testing.

nano .env

```Open a **second terminal** and run:



Paste this (use your real Supabase values):```bash

cloudflared tunnel --url http://localhost:3000

``````

SUPABASE_URL=https://rprpadtmqqttvxhojnmz.supabase.co

SUPABASE_KEY=your-supabase-service-role-key-hereAfter a few seconds, you'll see output like:

PORT=3000```

```+--------------------------------------------------------------------------------------------+

|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |

Save: press `Ctrl+X`, then `Y`, then `Enter`.|  https://random-words-here.trycloudflare.com                                               |

+--------------------------------------------------------------------------------------------+

---```



## Step 6 — Test the App✅ **That URL is your live deployed app!** Share it with anyone.



```bash> ⚠️ This URL changes every time you restart cloudflared. For a permanent URL, see Option B.

node server.js

```---



You should see:## Step 4 — Option B: Named Tunnel with Custom Domain (Permanent)



```### 4B.1 — Log in to Cloudflare

Server running on http://0.0.0.0:3000

✓ Database schema OK (phone, gender columns exist)```bash

```cloudflared login

```

Press `Ctrl+C` to stop the test.

This opens your browser. Select the domain you want to use and authorize.

---

### 4B.2 — Create a Named Tunnel

## Step 7 — Start the App with PM2 (Runs Forever)

```bash

PM2 keeps your app running 24/7 and auto-restarts it if it crashes or if the server reboots.cloudflared tunnel create zero-trust-demo

```

```bash

# Start the appThis creates a tunnel and outputs a **Tunnel ID** (e.g., `a1b2c3d4-...`). Note it down.

pm2 start server.js --name "zero-trust"

It also creates a credentials file at:

# Save the process list```

pm2 save~/.cloudflared/<TUNNEL-ID>.json

```

# Set PM2 to start on boot

pm2 startup### 4B.3 — Configure the Tunnel

```

Create a config file:

Copy and run the command that PM2 prints (it starts with `sudo env PATH=...`).

```bash

Check it's running:nano ~/.cloudflared/config.yml

```

```bash

pm2 statusPaste this (replace the values):

```

```yaml

You should see:tunnel: <YOUR-TUNNEL-ID>

credentials-file: /Users/rajan/.cloudflared/<YOUR-TUNNEL-ID>.json

```

┌─────┬─────────────┬─────────┬──────┬───────┬──────────┐ingress:

│ id  │ name        │ mode    │ ↺    │ status│ cpu      │  - hostname: zerotrust.yourdomain.com

├─────┼─────────────┼─────────┼──────┼───────┼──────────┤    service: http://localhost:3000

│ 0   │ zero-trust  │ fork    │ 0    │ online│ 0%       │  - service: http_status:404

└─────┴─────────────┴─────────┴──────┴───────┴──────────┘```

```

### 4B.4 — Add DNS Record

---

```bash

## Step 8 — Set Up Nginx (Reverse Proxy)cloudflared tunnel route dns zero-trust-demo zerotrust.yourdomain.com

```

Nginx will forward web traffic (port 80) to your Node.js app (port 3000).

This creates a CNAME record in Cloudflare DNS automatically.

```bash

sudo nano /etc/nginx/sites-available/zero-trust### 4B.5 — Run the Tunnel

```

```bash

Paste this entire block (replace `YOUR_SERVER_IP` with your IONOS IP):cloudflared tunnel run zero-trust-demo

```

```nginx

server {✅ Your app is now live at `https://zerotrust.yourdomain.com`

    listen 80;

    server_name YOUR_SERVER_IP;---



    location / {## Step 5 — Run Both Together (One Command)

        proxy_pass http://127.0.0.1:3000;

        proxy_http_version 1.1;You can start the server and tunnel together. Add this to `package.json` scripts:

        proxy_set_header Upgrade $http_upgrade;

        proxy_set_header Connection 'upgrade';```json

        proxy_set_header Host $host;"tunnel": "cloudflared tunnel --url http://localhost:3000",

        proxy_set_header X-Real-IP $remote_addr;"deploy": "npm start & sleep 2 && npm run tunnel"

        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;```

        proxy_cache_bypass $http_upgrade;

    }Then just run:

}```bash

```npm run deploy

```

Save: `Ctrl+X`, `Y`, `Enter`.

---

Enable the site and restart Nginx:

## Step 6 — Keep It Running (Optional - Background Service)

```bash

sudo ln -s /etc/nginx/sites-available/zero-trust /etc/nginx/sites-enabled/### macOS (launchd)

sudo rm /etc/nginx/sites-enabled/default```bash

sudo nginx -tcloudflared service install

sudo systemctl restart nginxbrew services start cloudflared

``````



✅ **Your app is now live at: `http://YOUR_SERVER_IP`**### Linux (systemd)

```bash

Open it in your browser!sudo cloudflared service install

sudo systemctl enable cloudflared

---sudo systemctl start cloudflared

```

## Step 9 — Add Free SSL (HTTPS)

---

### Option A: If you have a domain name

## Architecture

If you bought a domain (e.g. `zerotrust.rajanchand.com`):

```

1. Point your domain's **A record** to your IONOS server IP┌──────────┐     HTTPS      ┌────────────────┐     HTTP      ┌──────────────┐

2. Update the Nginx config — change `server_name YOUR_SERVER_IP` to `server_name zerotrust.rajanchand.com`│  Browser  │ ───────────── │  Cloudflare     │ ──────────── │  Your Mac    │

3. Install SSL:│  (User)   │               │  Edge Network   │              │  localhost   │

│           │               │  (DDoS + SSL)   │              │  :3000       │

```bash└──────────┘               └────────────────┘              └──────────────┘

sudo apt install certbot python3-certbot-nginx -y                                                                    │

sudo certbot --nginx -d zerotrust.rajanchand.com                                                                    ▼

```                                                            ┌──────────────┐

                                                            │  Supabase    │

Follow the prompts. SSL auto-renews every 90 days.                                                            │  (Database)  │

                                                            └──────────────┘

✅ **App is live at: `https://zerotrust.rajanchand.com`**```



### Option B: If you don't have a domain**Benefits:**

- ✅ Free SSL/HTTPS (automatic)

Your app works at `http://YOUR_SERVER_IP` without SSL. For a quick free domain, you can use:- ✅ DDoS protection

- [https://www.duckdns.org](https://www.duckdns.org) — free subdomain (e.g. `zerotrust.duckdns.org`)- ✅ No port forwarding needed

- IONOS also sells domains from £1/year- ✅ No static IP needed

- ✅ Works behind NAT/firewalls

---- ✅ Zero Trust access controls available



## Step 10 — Firewall Setup (Security)---



```bash## Troubleshooting

sudo ufw allow OpenSSH

sudo ufw allow 'Nginx Full'| Issue | Solution |

sudo ufw enable|-------|----------|

sudo ufw status| `cloudflared: command not found` | Reinstall: `brew install cloudflared` |

```| Tunnel URL not loading | Make sure `npm start` is running on port 3000 first |

| `ERR_CONNECTION_REFUSED` | Check `.env` has correct `PORT=3000` |

This only allows SSH (port 22) and web traffic (ports 80, 443).| Profile save fails | Run `migrate.sql` in Supabase SQL Editor |

| Tunnel stops when terminal closes | Use `cloudflared service install` for background running |

---

---

## Updating the App (After Code Changes)

## Quick Reference

When you push new code to GitHub, update the server:

| Command | What it does |

```bash|---------|-------------|

ssh root@YOUR_SERVER_IP| `npm start` | Start the app on localhost:3000 |

cd /var/www/Zero-trust-security-demo| `npm run start:dev` | Start with auto-reload (development) |

git pull origin main| `cloudflared tunnel --url http://localhost:3000` | Quick public URL (temporary) |

npm install| `cloudflared tunnel run zero-trust-demo` | Named tunnel (permanent domain) |

pm2 restart zero-trust| `npm run deploy` | Start app + tunnel together |

```

---

## Useful PM2 Commands

| Command | What It Does |
|---------|-------------|
| `pm2 status` | Check if app is running |
| `pm2 logs zero-trust` | View live logs |
| `pm2 restart zero-trust` | Restart the app |
| `pm2 stop zero-trust` | Stop the app |
| `pm2 delete zero-trust` | Remove the app from PM2 |
| `pm2 monit` | Live monitoring dashboard |

---

## Useful Nginx Commands

| Command | What It Does |
|---------|-------------|
| `sudo nginx -t` | Test config for errors |
| `sudo systemctl restart nginx` | Restart Nginx |
| `sudo systemctl status nginx` | Check Nginx status |

---

## Architecture

```
┌──────────┐     HTTPS/80    ┌─────────────────┐    :3000    ┌──────────────┐
│  Browser  │ ─────────────→ │  IONOS VPS       │ ─────────→ │  Node.js     │
│  (User)   │                │  Nginx (proxy)   │            │  Express App │
└──────────┘                └─────────────────┘            └──────┬───────┘
                                                                  │
                                                                  ▼
                                                          ┌──────────────┐
                                                          │  Supabase    │
                                                          │  PostgreSQL  │
                                                          │  (Free DB)   │
                                                          └──────────────┘
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Can't SSH into server | Check IP, password. Try: `ssh -v root@YOUR_IP` |
| `npm install` fails | Run `sudo apt install build-essential -y` then try again |
| App crashes on start | Check `.env` file exists with correct values |
| Nginx shows 502 Bad Gateway | App not running. Run `pm2 restart zero-trust` |
| Port 80 not accessible | Run `sudo ufw allow 'Nginx Full'` |
| Profile save fails | Run `migrate.sql` in Supabase SQL Editor |
| Site shows Nginx default page | Run `sudo rm /etc/nginx/sites-enabled/default && sudo systemctl restart nginx` |
