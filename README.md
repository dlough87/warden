# Warden

Warden automatically removes stale movies and TV shows from your Plex library. It works by connecting to Radarr and Sonarr (to manage your library) and Plex + Tautulli (to track what's been watched), then applies your own rules to decide what gets condemned and eventually deleted.

## Features

- **Rule-based culling** — define criteria by media type, watch status, rating, age, and more. Multiple rules, any match condemns an item.
- **Death row** — condemned items sit in a configurable holding period before deletion, giving you time to pardon anything you want to keep.
- **Dry run mode** — see exactly what would be deleted before you let it actually delete anything.
- **Scheduled scans** — runs automatically on a cron schedule you control.
- **Notifications** — Discord webhooks for condemned items, deletions, and clean scans.
- **Full web UI** — dashboard, library browser, rules editor, death row management, settings, audit log.
- **Account security** — username/password login, TOTP (2FA), passkeys (Face ID / Touch ID / Windows Hello).
- **Backup & restore** — export and import your configuration as JSON.

---

## Requirements

- Docker
- Radarr and/or Sonarr
- Plex Media Server
- Tautulli (optional, for watch history)

---

## Installation

### Docker Run

```bash
docker run -d \
  --name warden \
  -p 8787:8787 \
  -v /your/data/path:/data \
  --restart unless-stopped \
  ghcr.io/dlough87/warden:latest
```

Replace `/your/data/path` with a directory on your host where Warden will store its database.

### Docker Compose

```yaml
services:
  warden:
    image: ghcr.io/dlough87/warden:latest
    container_name: warden
    ports:
      - "8787:8787"
    volumes:
      - ./data:/data
    restart: unless-stopped
```

### Build from source

```bash
git clone https://github.com/yourusername/warden.git
cd warden
docker build -t warden .
docker run -d \
  --name warden \
  -p 8787:8787 \
  -v /your/data/path:/data \
  --restart unless-stopped \
  warden
```

---

## First-run setup

1. Open `http://your-server-ip:8787` in your browser
2. You'll be prompted to create an admin username and password
3. Go to **Settings → Connections** and enter your Radarr, Sonarr, Plex, and Tautulli details
4. Go to **Settings → General** and configure your scan schedule, death row period, and timezone
5. Create at least one rule under **Rules**
6. Run a scan from the **Dashboard** — in dry run mode first to review what would be affected
7. When you're happy, disable dry run in **Settings → General** and let Warden do its thing

---

## HTTPS and Passkeys

Warden supports passkeys (Face ID, Touch ID, Windows Hello) as a replacement for username + password login. Passkeys require HTTPS with a trusted certificate — self-signed certificates will not work.

If you're not already behind an HTTPS reverse proxy, two easy options:

### Cloudflare Tunnel (no open ports required)

1. Create a free [Cloudflare](https://www.cloudflare.com) account and add your domain
2. Set up a tunnel in the Cloudflare Zero Trust dashboard pointing to `http://localhost:8787`
3. Cloudflare handles the certificate automatically
4. Set **Passkey Domain** in Settings → General to your tunnel hostname (e.g. `warden.example.com`)

### Caddy (auto Let's Encrypt)

Add Caddy alongside Warden in your `docker-compose.yml`:

```yaml
services:
  warden:
    image: ghcr.io/dlough87/warden:latest
    container_name: warden
    volumes:
      - ./data:/data
    restart: unless-stopped

  caddy:
    image: caddy:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
    restart: unless-stopped

volumes:
  caddy_data:
```

`Caddyfile`:

```
warden.example.com {
    reverse_proxy warden:8787
}
```

Ports 80 and 443 must be reachable from the internet for Let's Encrypt to issue a certificate. Set **Passkey Domain** to your domain.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `WARDEN_PORT` | `8787` | Port the web server listens on |

All other configuration (connections, schedule, rules, notifications) is managed through the web UI and stored in the database.

---

## Data

Warden stores everything in a single SQLite database at `/data/warden.db` inside the container. Mount a host directory to `/data` to persist it across container restarts and updates.

The database contains your settings, rules, media item history, audit log, and account credentials. It does not contain any media files — Warden only instructs Radarr/Sonarr to delete items via their APIs.

---

## Support

See the built-in support guide at `http://your-server/support/guide` for full documentation on every feature.
