#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }
trap 'rc=$?; printf "[ERROR] deployment failed at line %s (exit %s). Existing PM2 processes were not intentionally stopped.\n" "$LINENO" "$rc" >&2; exit "$rc"' ERR

[[ -f .env ]] || die "Missing .env. Copy .env.production.example to .env and configure unique production secrets first."
[[ -f alembic.ini ]] || die "alembic.ini was not found at repository root; refusing to guess migration configuration."
command -v node >/dev/null || die "Node.js is required."
command -v npm >/dev/null || die "npm is required."
command -v python3 >/dev/null || die "Python 3 is required."
command -v pm2 >/dev/null || die "PM2 is required. Install it globally before deployment."
node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(a<20)process.exit(1)' || die "Node.js 20+ is required."
python3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,11) else 1)' || die "Python 3.11+ is required."
grep -Eq '^WGM_JWT_SECRET=.{32,}$' .env || die "WGM_JWT_SECRET must be set to a unique random secret of at least 32 characters."
grep -Eq '^WGM_ENCRYPTION_KEY=.{40,}$' .env || die "WGM_ENCRYPTION_KEY must be set to a valid Fernet key."
grep -Eq '^WGM_DATABASE_URL=.+$' .env || die "WGM_DATABASE_URL must be explicitly configured for persistent production storage."
grep -Eq '^WGM_ALLOWED_ORIGINS=.+$' .env || die "Set WGM_ALLOWED_ORIGINS to the exact production origin."
grep -Eq '^WGM_BOOTSTRAP_ADMIN_USERNAME=.+$' .env || log "No bootstrap admin configured. Provision the first admin through the one-time bootstrap procedure after deployment."

log "Creating/updating isolated Python environment"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .

log "Installing locked frontend dependencies"
npm install --no-audit --no-fund

log "Building the production-only frontend (demo dashboard is not an entry point)"
npm run build:production
[[ -f dist-production/index.production.html ]] || die "Production build did not create dist-production/index.production.html."
if grep -R -E 'Demo workspace initialized|dev-001|Staging Gateway|sample routers loaded|wg-manager-demo-v2' dist-production --include='*.js' --include='*.html'; then
  die "Synthetic demo fixture markers were found in the production bundle."
fi

log "Applying database migrations (no demo seed or database reset)"
PYTHONPATH=backend .venv/bin/alembic upgrade head

log "Starting/reloading production processes through PM2"
pm2 startOrReload ecosystem.config.cjs --update-env
pm2 save

log "Checking local process health"
for attempt in $(seq 1 20); do
  if curl --fail --silent http://127.0.0.1:8000/healthz >/dev/null && curl --fail --silent http://127.0.0.1:4173/healthz >/dev/null; then break; fi
  [[ "$attempt" -lt 20 ]] || die "Health checks failed. Inspect: pm2 logs wireguard-manager-api and pm2 logs wireguard-manager-web"
  sleep 2
done
curl --fail --silent http://127.0.0.1:8000/api/v1/health
printf '\n'

# Bootstrap the first administrator once. The API rejects this after any user exists.
if grep -Eq '^WGM_BOOTSTRAP_ADMIN_USERNAME=.+ Web: http://127.0.0.1:4173 (binds to loopback); API: http://127.0.0.1:8000 (binds to loopback). Put a TLS reverse proxy in front before remote use."
log "First-run admin bootstrap, if configured, must be invoked once over the private host: POST /api/v1/admin/bootstrap; then remove bootstrap credentials from .env and restart the API."
 .env && grep -Eq '^WGM_BOOTSTRAP_ADMIN_PASSWORD=.+ Web: http://127.0.0.1:4173 (binds to loopback); API: http://127.0.0.1:8000 (binds to loopback). Put a TLS reverse proxy in front before remote use."
log "First-run admin bootstrap, if configured, must be invoked once over the private host: POST /api/v1/admin/bootstrap; then remove bootstrap credentials from .env and restart the API."
 .env; then
  log "Attempting one-time administrator bootstrap"
  response="$(curl --silent --show-error --output /tmp/wgm-bootstrap-response.$ --write-out '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/admin/bootstrap || true)"
  case "$response" in
    201) log "Initial administrator created. Use the username/password configured in .env." ;;
    409) log "Database already contains users; bootstrap was not repeated." ;;
    *) cat /tmp/wgm-bootstrap-response.$ >&2 || true; rm -f /tmp/wgm-bootstrap-response.$; die "Administrator bootstrap failed with HTTP $response." ;;
  esac
  rm -f /tmp/wgm-bootstrap-response.$
  python3 - <<'PY'
from pathlib import Path
p = Path(".env")
lines = p.read_text().splitlines()
blocked = ("WGM_BOOTSTRAP_ADMIN_USERNAME=", "WGM_BOOTSTRAP_ADMIN_PASSWORD=")
p.write_text("\n".join(line for line in lines if not line.startswith(blocked)) + "\n")
PY
  chmod 600 .env
  log "Removed one-time bootstrap credentials from .env."
fi

log "Deployment checks passed. Web: http://127.0.0.1:4173 (binds to loopback); API: http://127.0.0.1:8000 (binds to loopback). Put a TLS reverse proxy in front before remote use."
log "First-run admin bootstrap, if configured, must be invoked once over the private host: POST /api/v1/admin/bootstrap; then remove bootstrap credentials from .env and restart the API."
