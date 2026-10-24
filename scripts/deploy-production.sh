#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }
trap 'rc=$?; printf "[ERROR] deployment failed at line %s (exit %s). Existing PM2 processes were not intentionally stopped.\n" "$LINENO" "$rc" >&2; exit "$rc"' ERR

[[ -f .env ]] || die "Missing .env. Copy .env.production.example to .env and configure unique production secrets first."
chmod 600 .env
[[ -f alembic.ini ]] || die "alembic.ini was not found at repository root."
command -v node >/dev/null || die "Node.js is required."
command -v npm >/dev/null || die "npm is required."
command -v python3 >/dev/null || die "Python 3 is required."
command -v pm2 >/dev/null || die "PM2 is required. Install it globally before deployment."
command -v curl >/dev/null || die "curl is required for health checks."
node -e 'const [a]=process.versions.node.split(".").map(Number);if(a<20)process.exit(1)' || die "Node.js 20+ is required."
python3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,11) else 1)' || die "Python 3.11+ is required."

grep -Eq '^WGM_JWT_SECRET=.{32,}$' .env || die "WGM_JWT_SECRET must be at least 32 characters."
grep -Eq '^WGM_JWT_SECRET=(REPLACE|CHANGE_ME|example|changeme)' .env && die "Replace the JWT placeholder with a generated random secret."
grep -Eq '^WGM_ENCRYPTION_KEY=.{40,}$' .env || die "WGM_ENCRYPTION_KEY must be a valid Fernet key."
grep -Eq '^WGM_ENCRYPTION_KEY=(REPLACE|CHANGE_ME|example|changeme)' .env && die "Replace the encryption-key placeholder."
grep -Eq '^WGM_DATABASE_URL=.+$' .env || die "Set WGM_DATABASE_URL to a persistent database."
grep -Eq '^WGM_ALLOWED_ORIGINS=.+$' .env || die "Set WGM_ALLOWED_ORIGINS to the exact production origin."
if grep -Eq '^WGM_BOOTSTRAP_ADMIN_USERNAME=.+$' .env; then
  grep -Eq '^WGM_BOOTSTRAP_ADMIN_PASSWORD=.{12,}$' .env || die "Bootstrap password must be at least 12 characters."
  grep -Eq '^WGM_BOOTSTRAP_ADMIN_USERNAME=(CHANGE_ME|REPLACE|example)' .env && die "Replace the bootstrap username placeholder."
  grep -Eq '^WGM_BOOTSTRAP_ADMIN_PASSWORD=(REPLACE|CHANGE_ME|example|changeme)' .env && die "Replace the bootstrap password placeholder."
fi

log "Creating/updating isolated Python environment"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
.venv/bin/python - <<'PY'
from pathlib import Path
from cryptography.fernet import Fernet
values = {}
for line in Path(".env").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        values[key] = value
Fernet(values["WGM_ENCRYPTION_KEY"].encode("ascii"))
if len(values["WGM_JWT_SECRET"]) < 32:
    raise SystemExit("WGM_JWT_SECRET is too short")
PY

log "Installing frontend dependencies"
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
  [[ "$attempt" -lt 20 ]] || die "Health checks failed. Inspect PM2 logs for both processes."
  sleep 2
done
curl --fail --silent http://127.0.0.1:8000/api/v1/health
printf '\n'

if grep -Eq '^WGM_BOOTSTRAP_ADMIN_USERNAME=.+$' .env && grep -Eq '^WGM_BOOTSTRAP_ADMIN_PASSWORD=.+$' .env; then
  log "Attempting one-time administrator bootstrap"
  response_file="$(mktemp)"
  response_code="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/admin/bootstrap || true)"
  case "$response_code" in
    201) log "Initial administrator created. Use the configured credentials." ;;
    409) log "Database already contains a user; bootstrap was not repeated." ;;
    *) cat "$response_file" >&2 || true; rm -f "$response_file"; die "Administrator bootstrap failed with HTTP $response_code." ;;
  esac
  rm -f "$response_file"
  python3 - <<'PY'
from pathlib import Path
p = Path(".env")
lines = p.read_text().splitlines()
blocked = ("WGM_BOOTSTRAP_ADMIN_USERNAME=", "WGM_BOOTSTRAP_ADMIN_PASSWORD=")
p.write_text("\n".join(line for line in lines if not line.startswith(blocked)) + "\n")
PY
  chmod 600 .env
  log "Removed one-time bootstrap credentials from .env."
else
  log "No bootstrap credentials configured; no administrator account was created."
fi

log "Deployment health checks passed."
log "Web listener: 127.0.0.1:4173; API listener: 127.0.0.1:8000. Put a TLS reverse proxy in front before remote use."
