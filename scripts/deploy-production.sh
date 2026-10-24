#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '\n[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

need node
need npm
need python3
need pm2
need curl
node -e 'const [major,minor]=process.versions.node.split(".").map(Number); const ok=(major===20 && minor>=19) || (major===22 && minor>=12) || major>22; process.exit(ok ? 0 : 1)' || die "Node.js 20.19+ or 22.12+ is required."
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required.")
PY

if [[ ! -f .env ]]; then
  log "Creating a new production .env with unique secrets."
  mkdir -p data logs
  read -r -p "Initial administrator username: " ADMIN_USER
  [[ -n "$ADMIN_USER" ]] || die "Admin username cannot be empty."
  read -r -s -p "Initial administrator password (minimum 12 characters): " ADMIN_PASS
  printf '\n'
  [[ "${#ADMIN_PASS}" -ge 12 ]] || die "Password must contain at least 12 characters."
  read -r -s -p "Confirm administrator password: " ADMIN_CONFIRM
  printf '\n'
  [[ "$ADMIN_PASS" == "$ADMIN_CONFIRM" ]] || die "Passwords do not match."

  [[ -d .venv ]] || python3 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip >/dev/null
  .venv/bin/python -m pip install 'cryptography>=43,<47' >/dev/null
  ADMIN_PASS_ESC="$(printf '%s' "$ADMIN_PASS" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read(), ensure_ascii=False))')"
  JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  ENC_KEY="$(.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

  cat > .env <<EOF
WGM_ENV=production
WGM_DATABASE_URL=sqlite:///$ROOT/data/wireguard-manager.db
WGM_JWT_SECRET=$JWT_SECRET
WGM_ENCRYPTION_KEY=$ENC_KEY
WGM_ACCESS_TOKEN_MINUTES=15
WGM_BOOTSTRAP_ADMIN_USERNAME=$ADMIN_USER
WGM_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASS_ESC
WGM_ALLOWED_ORIGINS=
WGM_ALLOW_PUBLIC_ROUTER_HOSTS=false
WGM_ALLOW_PUBLIC_LINUX_HOSTS=false
WGM_ENABLE_PEER_MUTATIONS=false
WGM_ENABLE_LINUX_MUTATIONS=false
WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=false
EOF
  unset ADMIN_PASS ADMIN_PASS_ESC ADMIN_CONFIRM JWT_SECRET ENC_KEY
  chmod 600 .env
  printf '%s\n' "$ADMIN_USER" > .first-admin-username
  chmod 600 .first-admin-username
fi

# Refuse to start the demo/dev backend or silently use placeholder secrets.
grep -q '^WGM_ENV=production$' .env || die "The existing .env must contain WGM_ENV=production; refusing to start in development/demo mode."
grep -Eq '^WGM_JWT_SECRET=.{32,}$' .env || die "WGM_JWT_SECRET is missing or too short in .env."
grep -Eq '^WGM_ENCRYPTION_KEY=.+$' .env || die "WGM_ENCRYPTION_KEY is missing in .env."

[[ -d .venv ]] || python3 -m venv .venv
mkdir -p data logs
chmod 700 data logs

log "Installing backend dependencies."
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .

log "Installing frontend dependencies."
npm install
log "Building production UI (API-backed; no demo seed data)."
VITE_APP_MODE=production npm run build

log "Applying reviewed Alembic migrations."
.venv/bin/alembic upgrade head

log "Starting/reloading API under PM2."
pm2 startOrReload ecosystem.config.cjs --update-env
pm2 save

if [[ -f .first-admin-username ]]; then
  log "Waiting for API before one-time admin bootstrap."
  for _ in $(seq 1 40); do
    if curl --silent --fail http://127.0.0.1:8000/healthz >/dev/null; then break; fi
    sleep 1
  done
  curl --silent --show-error --fail http://127.0.0.1:8000/healthz >/dev/null || die "API did not become healthy; inspect PM2 logs."
  BOOTSTRAP_CODE="$(curl --silent --show-error --output /tmp/wgm-bootstrap-response.json --write-out '%{http_code}' -X POST http://127.0.0.1:8000/api/v1/admin/bootstrap)"
  if [[ "$BOOTSTRAP_CODE" != "201" ]]; then
    cat /tmp/wgm-bootstrap-response.json >&2 || true
    die "Admin bootstrap failed (HTTP $BOOTSTRAP_CODE). Inspect the DB and logs; do not rerun blindly."
  fi
  python3 - "$ROOT/.env" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
lines = p.read_text().splitlines()
lines = [line for line in lines if not line.startswith(("WGM_BOOTSTRAP_ADMIN_USERNAME=", "WGM_BOOTSTRAP_ADMIN_PASSWORD="))]
p.write_text("\n".join(lines) + "\n")
p.chmod(0o600)
PY
  rm -f .first-admin-username /tmp/wgm-bootstrap-response.json
  log "Initial admin created; bootstrap credentials removed from .env."
  pm2 restart wireguard-manager --update-env
  pm2 save
fi

log "Deployment complete."
printf '\nProduction UI: http://127.0.0.1:8000\nAPI health: http://127.0.0.1:8000/healthz\n'
printf 'PM2 status: pm2 status\nPM2 logs: pm2 logs wireguard-manager\n'
printf 'Manage: pm2 restart wireguard-manager | pm2 stop wireguard-manager | pm2 save\n'
printf '\nThe service binds to loopback. Put it behind a TLS reverse proxy before remote access.\n'
printf 'Back up data/wireguard-manager.db and the WGM_ENCRYPTION_KEY in .env securely.\n'
