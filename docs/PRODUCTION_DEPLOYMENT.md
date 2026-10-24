# Production deployment (PM2)

The production deployment is deliberately separate from the GitHub Pages demo. It builds only `index.production.html` and `src/production-main.tsx`; the sample dashboard and synthetic fixture data are not imported into the production artifact. The production UI reads authenticated data from FastAPI and starts with empty inventories when the database is empty.

## Host requirements

- Linux host; Node.js 20+, npm, Python 3.11+, curl, and PM2 installed for the deployment user.
- A private management network or TLS reverse proxy in front of the loopback-bound web listener. Do not expose ports 4173 or 8000 directly to the internet.
- Connectivity from the host to the RouterOS HTTPS REST endpoints and SSH targets that will be registered.
- Backups for the database and the encryption key. Losing `WGM_ENCRYPTION_KEY` makes stored credentials and peer private keys unreadable.
- A reviewed backup/restore procedure before managing production infrastructure.

## Initial configuration (once per host)

From the cloned repository directory:

```bash
cp .env.production.example .env
chmod 600 .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Put the generated values into `WGM_JWT_SECRET` and `WGM_ENCRYPTION_KEY`. Set a unique initial admin username/password, the exact external origin in `WGM_ALLOWED_ORIGINS`, and a persistent `WGM_DATABASE_URL`. The example uses a local SQLite database in the repository directory for a single-host install; evaluate PostgreSQL and configure its SQLAlchemy driver before using it for a multi-user/high-volume deployment.

The bootstrap password must be at least 12 characters. Do not use any example or placeholder value. Keep the environment file private. Never commit it.

## Deploy or upgrade with one command

```bash
bash scripts/deploy-production.sh
```

The script validates host tools and essential configuration, installs backend/frontend dependencies, builds the production-only frontend, rejects known demo-fixture markers in the generated bundle, applies Alembic migrations, starts/reloads the API and web processes in PM2, checks health endpoints, and attempts the one-time administrator bootstrap. It does not seed demonstration routers/devices, reset the database, or drop tables.

After a successful first bootstrap, the script removes the one-time bootstrap username/password from `.env`. Keep the admin password in a password manager. Subsequent runs do not recreate the administrator.

## Process management

```bash
pm2 status
pm2 logs wireguard-manager-api
pm2 logs wireguard-manager-web
pm2 restart wireguard-manager-api
pm2 restart wireguard-manager-web
pm2 save
```

PM2 process definitions are in `ecosystem.config.cjs`. The web server listens on `127.0.0.1:4173`, proxies same-origin `/api/*` requests to FastAPI at `127.0.0.1:8000`, and serves the built static files. Configure your TLS reverse proxy to forward to port 4173. Preserve the original host/proto headers as appropriate for your proxy and set the exact external origin in `WGM_ALLOWED_ORIGINS`.

## First login and live operations

Sign in with the initial administrator credentials. Register a RouterOS device using an account limited to the required read/write REST resources, then run **Test connection** and inspect discovery/diagnostics before using the system operationally. Register Linux servers only after independently verifying the SSH host-key fingerprint.

Peer mutations and Linux install/optimizer mutations remain disabled by default. They must stay disabled until tested on the exact RouterOS/Linux versions, rollback paths, firewall ordering, and change-control process used in your environment. The UI must not imply that disabled operations succeeded.

## Scope and known limitations

- The production UI includes login, live router inventory/registration/connectivity checks, live peer discovery and point-in-time counters, bounded diagnostics and router audit, Linux server registration/inspection/remote peer discovery, and admin user creation.
- Historical traffic charts, alerting, and traffic retention are not implemented by the backend; current counters are point-in-time only.
- The production UI still needs the full peer lifecycle workflow (preview/create/revoke), client configuration/QR delivery, per-peer ACL editing, and complete audit-event browsing before it can be considered feature-complete.
- A successful deployment script/health check does not prove connectivity to every registered router/server. Test those connections and verify backups/restores before operational use.
- The deployment script has not deployed to or been validated on your host. Review the generated PR and CI results before merging it into `main`.
