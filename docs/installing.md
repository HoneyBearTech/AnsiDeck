# Installing

This runs a released version of AnsiDeck in production from the published container images, with Docker
Compose, behind a reverse proxy that terminates HTTPS. For a quick local try-out, see
[quick-start.md](quick-start.md).

AnsiDeck is meant for a trusted network: don't expose it directly to the internet (see
[security.md](security.md)).

## What you need

- A Linux host with Docker Engine 26 or later (the compose file mounts a volume subpath) and Docker
  Compose v2.
- A DNS name for AnsiDeck and a reverse proxy that serves it over HTTPS (Caddy, nginx, Traefik, …).
- Network access from that host to the machines your playbooks manage, over SSH.

The images are `ghcr.io/honeybeartech/ansideck-backend` (the API and the workers) and
`ghcr.io/honeybeartech/ansideck-frontend` (the web UI). Each release is signed; check them with
[verifying-releases.md](verifying-releases.md) before you start.

## 1. Get the deployment files

Download `compose.yaml` and `.env.example` from the [`deploy/` folder](../deploy) of the release you install
(for v0.3.0: `https://raw.githubusercontent.com/HoneyBearTech/AnsiDeck/v0.3.0/deploy/compose.yaml`), into a
directory of their own, for example `/opt/ansideck`:

```sh
sudo mkdir -p /opt/ansideck && cd /opt/ansideck
sudo curl -fsSLO https://raw.githubusercontent.com/HoneyBearTech/AnsiDeck/v0.3.0/deploy/compose.yaml
sudo curl -fsSL -o .env https://raw.githubusercontent.com/HoneyBearTech/AnsiDeck/v0.3.0/deploy/.env.example
```

## 2. Create the secrets

Secrets live in files under `secrets/`, which Compose hands to the containers as Docker secrets. Only the
database and the API see them; the workers get none. Generate them once:

```sh
sudo mkdir -p secrets
pw=$(openssl rand -hex 24)
printf '%s\n' "$pw" | sudo tee secrets/postgres_password >/dev/null
printf 'postgresql+psycopg://ansideck:%s@postgres:5432/ansideck\n' "$pw" | sudo tee secrets/database_url >/dev/null
openssl rand -hex 32 | sudo tee secrets/auth_secret_key >/dev/null
python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" \
  | sudo tee secrets/credential_encryption_key >/dev/null
printf 'Password for the first admin: '; stty -echo; read -r admin; stty echo; echo
printf '%s\n' "$admin" | sudo tee secrets/admin_password >/dev/null
sudo chmod 700 secrets && sudo chmod 444 secrets/*
```

The directory is closed to other users on the host. The files themselves must stay readable, because the
database (uid 999) and the API (uid 1000) read them inside their containers.

- `credential_encryption_key` encrypts every stored SSH key, vault password and token. **Back it up
  separately** (for example in your password manager): without it, a database backup can't be decrypted,
  and anyone who has both can decrypt everything.
- `admin_password` is only used to create the first admin, on the very first start. Change it later under
  **Account**, and turn on two-factor login there.

## 3. Set the remaining settings

Edit `.env`: set `WORKER_TOKEN` to a long random string (`openssl rand -hex 32`), and check
`ANSIDECK_VERSION`. The workers need this token in their environment rather than a file: Compose makes
secret files readable to every user in a container, and a worker runs playbooks as other users, which must
not see it. Optional settings (single sign-on, notifications by email, a secret store, metrics) are listed
in the [README](../README.md); add them to the `environment:` of the `backend` service.

## 4. Start it

```sh
sudo docker compose up -d --wait
sudo docker compose ps
```

The API creates and migrates the database on start-up. `postgres`, `backend` and `worker` should be
running, and `postgres` and `backend` healthy. The web UI now answers on `127.0.0.1:8080`.

Add workers or slots when runs queue up: `docker compose up -d --scale worker=3`, or a higher
`WORKER_SLOTS` (runs per worker at once).

## 5. Put HTTPS in front

Point your reverse proxy at `127.0.0.1:8080`. It must pass WebSocket upgrades (live run output uses
them), the original `Host` header and the client's address in `X-Forwarded-For`, and should add HSTS. With [Caddy](https://caddyserver.com/), which
gets a certificate by itself and handles WebSockets:

```caddyfile
ansideck.example.com {
    reverse_proxy 127.0.0.1:8080
    header Strict-Transport-Security "max-age=31536000"
}
```

With nginx:

```nginx
server {
    listen 443 ssl;
    server_name ansideck.example.com;
    # ssl_certificate / ssl_certificate_key ...
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h; # long runs keep their output stream open
    }
}
```

The frontend container already sends a Content-Security-Policy and other browser hardening headers; don't
strip them. If the proxy changes the `Host` header, add the public origin to `CORS_ORIGINS` in `.env`.

The frontend takes the client's address from `X-Forwarded-For` only when the request comes from a proxy it
trusts: by default the Docker gateway, which is where a proxy on the same host reaches `127.0.0.1:8080`
from. For a proxy in another container or on another machine, list its address or network in
`TRUSTED_PROXIES` in `.env` (for example `TRUSTED_PROXIES=gateway,172.30.0.0/16`). Check the result under
**Audit**: sign-ins should show your own address, not one shared address. The API, in turn, trusts the
address only from the frontend container (`TRUSTED_PROXY_HOSTS`, default `frontend`).

## 6. Sign in

Open `https://ansideck.example.com`, sign in as `admin` with the password you chose, and work through the
[quick start](quick-start.md#2-add-what-a-run-needs) from step 2. Then:

- create projects and users, or connect single sign-on ([user guide](user-guide/projects-and-users.md));
- set up a notification channel for failed runs and security alerts
  ([notifications](user-guide/notifications.md));
- schedule backups ([upgrading.md](upgrading.md#back-up)).

## Uninstalling

```sh
cd /opt/ansideck
sudo docker compose down        # stops and removes the containers; data stays in the volumes
sudo docker compose down -v     # also deletes the database and run history: this can't be undone
sudo docker image rm ghcr.io/honeybeartech/ansideck-backend:0.3.0 ghcr.io/honeybeartech/ansideck-frontend:0.3.0
```

Then delete `/opt/ansideck`, including `secrets/` (or keep `credential_encryption_key` with your backups
if you might restore one).
