# EdgeKeeper — Production Deployment Checklist

> Stack: Node.js/Express · Supabase · OpenAI · ElevenLabs · Polar.sh · Resend  
> Target: Ubuntu 22.04 VPS (DigitalOcean / Hetzner / Linode) behind nginx

---

## 1. Server Provisioning

1. Spin up a VPS with at least **2 vCPU / 2 GB RAM** (4 GB recommended for headroom).
2. Point your domain `edgekeeper.io` (and `www.edgekeeper.io`) at the server's public IP via an **A record** in your DNS panel. Allow up to 1 hour for propagation.
3. SSH in as root, then create a deploy user:

```bash
adduser deploy
usermod -aG sudo deploy
# copy your SSH public key to /home/deploy/.ssh/authorized_keys
```

---

## 2. Install Runtime Dependencies

```bash
# As root or with sudo
apt update && apt upgrade -y
apt install -y nginx certbot python3-certbot-nginx git curl

# Node.js 20 LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# PM2 process manager (global)
npm install -g pm2
```

---

## 3. Deploy Application Code

```bash
# As deploy user
mkdir -p /srv/edgekeeper
cd /srv/edgekeeper

# Option A — git clone (recommended)
git clone https://github.com/YOUR_ORG/edgekeeper.git .

# Option B — rsync from local machine (run from your machine)
# rsync -avz --exclude node_modules --exclude .env \
#   "C:/Users/ASUS/OneDrive/Documents/Edgekeeper/" deploy@YOUR_IP:/srv/edgekeeper/

cd /srv/edgekeeper
npm install --omit=dev
```

---

## 4. Environment Variables

Create `/srv/edgekeeper/.env` — **never commit this file**.

```bash
# /srv/edgekeeper/.env

NODE_ENV=production
PORT=3000
HOST=127.0.0.1

# Your production domain — must match exactly (no trailing slash)
# CORS will block requests from any other origin.
APP_URL=https://edgekeeper.io

# Supabase
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_ANON_KEY=eyJ...          # public anon key — safe to expose to browsers
SUPABASE_SERVICE_ROLE_KEY=eyJ...  # KEEP SECRET — never expose client-side

# OpenAI
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini          # or gpt-5.5 when available in your account

# ElevenLabs
ELEVENLABS_API_KEY=sk_...
ELEVENLABS_MIKE_AGENT_ID=agent_...
ELEVENLABS_ASHLEY_AGENT_ID=agent_...

# Resend — transactional email
RESEND_API_KEY=re_...
RESEND_FROM=EdgeKeeper <noreply@edgekeeper.io>

# Polar.sh — billing (get from polar.sh/settings)
POLAR_ACCESS_TOKEN=polar_at_...
POLAR_WEBHOOK_SECRET=whsec_...
POLAR_PRODUCT_STARTER_MONTHLY=prod_...
POLAR_PRODUCT_STARTER_ANNUAL=prod_...
POLAR_PRODUCT_PRO_MONTHLY=prod_...
POLAR_PRODUCT_PRO_ANNUAL=prod_...
POLAR_PRODUCT_PROFESSIONAL_MONTHLY=prod_...
POLAR_PRODUCT_PROFESSIONAL_ANNUAL=prod_...
POLAR_PRODUCT_INSTITUTIONAL_MONTHLY=prod_...
POLAR_PRODUCT_INSTITUTIONAL_ANNUAL=prod_...

# Admin
ADMIN_EMAIL=alexandermwhitmore@gmail.com
CONTACT_EMAIL=hello@edgekeeper.io
```

Lock down the file so only the deploy user can read it:

```bash
chmod 600 /srv/edgekeeper/.env
chown deploy:deploy /srv/edgekeeper/.env
```

---

## 5. SSL Certificate (Let's Encrypt)

```bash
# Obtain certificate — certbot will auto-configure nginx
certbot --nginx -d edgekeeper.io -d www.edgekeeper.io

# Verify auto-renewal works
certbot renew --dry-run
```

Certbot installs a systemd timer that renews certs automatically. No manual cron needed.

---

## 6. nginx Configuration

Create `/etc/nginx/sites-available/edgekeeper`:

```nginx
# Redirect www → apex
server {
    listen 80;
    listen [::]:80;
    server_name www.edgekeeper.io edgekeeper.io;
    return 301 https://edgekeeper.io$request_uri;
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name edgekeeper.io;

    # Managed by certbot — do not edit manually
    ssl_certificate     /etc/letsencrypt/live/edgekeeper.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/edgekeeper.io/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Harden TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Proxy to Node — never exposed directly to the internet
    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;

        # Required for WebSocket (ElevenLabs SDK handshake)
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Pass real client IP so rate limiting works correctly
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long AI responses
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # Body size limit (matches express.json limit)
        client_max_body_size 1m;
    }

    # Polar.sh webhook needs raw body for HMAC verification — no buffering issues expected at 1mb
    location /api/billing/webhook {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 1m;
    }

    # Block dot files at nginx level (belt + suspenders)
    location ~ /\. {
        deny all;
        return 404;
    }

    # Logs
    access_log /var/log/nginx/edgekeeper_access.log;
    error_log  /var/log/nginx/edgekeeper_error.log warn;
}
```

Enable the site and reload:

```bash
ln -s /etc/nginx/sites-available/edgekeeper /etc/nginx/sites-enabled/
nginx -t          # must print "syntax is ok"
systemctl reload nginx
```

---

## 7. PM2 Process Manager

```bash
cd /srv/edgekeeper

# Start with PM2
pm2 start server.js --name edgekeeper --env production

# Auto-start on reboot
pm2 startup systemd
# Copy and run the command it prints, then:
pm2 save

# Useful commands
pm2 status
pm2 logs edgekeeper --lines 100
pm2 reload edgekeeper        # zero-downtime reload
pm2 restart edgekeeper       # hard restart
```

---

## 8. Firewall (ufw)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 'Nginx Full'   # ports 80 + 443
ufw enable
ufw status
```

Port 3000 is NOT opened — Node only listens on 127.0.0.1 and nginx proxies to it.

---

## 9. Supabase Configuration (manual steps in dashboard)

1. **Auth → URL Configuration**
   - Site URL: `https://edgekeeper.io`
   - Redirect URLs: `https://edgekeeper.io/**`
   - Remove `localhost` entries from redirect allowlist in production.

2. **Auth → Cookies**
   - If configuring via Supabase dashboard: set `SameSite=Strict` on the session cookie.
   - This is the primary CSRF defence for cookie-based auth.

3. **Row Level Security** — verify RLS is enabled on every table:
   - `user_profiles`, `notebooks`, `journal_entries`, `message_usage`, `subscriptions`
   - The service role key bypasses RLS (which is intentional for server-side ops), but RLS still matters if you ever add client-direct Supabase calls.

4. **Edge Functions** — if any are deployed, confirm they do not use the anon key for privileged operations.

---

## 10. Polar.sh Webhook Registration

In your Polar.sh dashboard:

1. Go to **Settings → Webhooks**
2. Add webhook URL: `https://edgekeeper.io/api/billing/webhook`
3. Select events: `subscription.created`, `subscription.updated`, `subscription.active`, `subscription.canceled`, `subscription.revoked`, `order.created`
4. Copy the generated **webhook secret** and set it as `POLAR_WEBHOOK_SECRET` in your `.env` (include the `whsec_` prefix).

---

## 11. Verify Deployment

```bash
# Check Node is running and not exposed to the internet
ss -tlnp | grep 3000    # should show 127.0.0.1:3000 only, not 0.0.0.0:3000

# Check nginx is forwarding
curl -I https://edgekeeper.io    # should return 200 with security headers

# Check rate limiting works (run from a real IP, not localhost)
for i in $(seq 1 35); do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://edgekeeper.io/api/chat \
  -H "Content-Type: application/json" \
  -d '{}'; done
# Should see 429s after the 30th request

# Check dotfiles are blocked
curl -I https://edgekeeper.io/.env   # must return 404, never 200
```

---

## 12. Ongoing Operations

| Task | Command |
|------|---------|
| View live logs | `pm2 logs edgekeeper` |
| Deploy new code | `git pull && npm install --omit=dev && pm2 reload edgekeeper` |
| Rotate a secret | Update `.env` then `pm2 reload edgekeeper` |
| Renew SSL manually | `certbot renew` (normally automatic) |
| DB migrations | `npm run db:push` (from the server, with `.env` loaded) |
| View nginx errors | `tail -f /var/log/nginx/edgekeeper_error.log` |

---

## Red Flags to Address Before Launch

- [ ] Remove `'unsafe-eval'` from the CSP `script-src` directive once you audit which scripts actually need it. This is the highest-risk remaining CSP gap.
- [ ] Replace `'unsafe-inline'` scripts with CSP nonces in a follow-up pass — this neutralises XSS from any injected content.
- [ ] Set a Polar.sh webhook **IP allowlist** at the nginx level for additional webhook hardening (check Polar.sh docs for their published IP ranges).
- [ ] Consider adding `compression` middleware (`npm install compression`) before `express.static` for bandwidth savings — no security impact, pure performance.
- [ ] Add structured logging (e.g. `pino`) so PM2 log files are parseable by a log aggregator in future.
- [ ] Run `npm audit` before first deploy and pin any high/critical CVEs.
