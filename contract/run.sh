#!/usr/bin/env bash
# Build one implementation, migrate its database, start it with the test env, run the contract suite, stop it.
#   contract/run.sh go|rust|python|nestjs      (needs `make infra` running)
set -euo pipefail
lang="${1:?usage: contract/run.sh go|rust|python|nestjs}"
root="$(cd "$(dirname "$0")/.." && pwd)"

case "$lang" in
  go)     port=8081; build="go build -o bin/api ./cmd/api"; migrate="bin/api migrate up";              start="bin/api" ;;
  rust)   port=8082; build="cargo build --quiet";           migrate="target/debug/boilerplate migrate"; start="target/debug/boilerplate serve" ;;
  python) port=8083; build="uv sync --quiet";               migrate="uv run alembic upgrade head";     start="uv run python -m app" ;;
  nestjs) port=8084; build="pnpm install --frozen-lockfile --silent && pnpm --silent build"; migrate="pnpm exec prisma migrate deploy"; start="node dist/main.js" ;;
  *) echo "unknown implementation: $lang" >&2; exit 2 ;;
esac

export PORT=$port APP_ENV=development APP_URL=http://localhost:3000
export DATABASE_URL="postgres://postgres:postgres@localhost:5433/boilerplate_$lang?sslmode=disable"
export JWT_SECRET=contract-test-secret-0123456789abcdef
export RATE_LIMIT_AUTH_PER_MINUTE=100000 CORS_ORIGINS=http://localhost:3000
export TRUSTED_PROXY_HOPS=1 TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128 EMAIL_TOKEN_COOLDOWN_SECONDS=0
export SMTP_HOST=localhost SMTP_PORT=1025
export S3_ENDPOINT=http://localhost:9000 S3_REGION=auto S3_BUCKET=boilerplate
export S3_ACCESS_KEY_ID=minioadmin S3_SECRET_ACCESS_KEY=minioadmin

cd "$root/$lang"
eval "$build"
eval "$migrate" >/dev/null
# Refuse to run against someone else's listener: the suite would test the wrong server and report a false green.
if lsof -ti "tcp:$port" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $port is already in use; stop that process first" >&2; exit 1; fi
log="$(mktemp)"
$start >"$log" 2>&1 &
server=$!
# Stop only the process this script started (and its children), never whatever happens to listen on the port.
cleanup() { pkill -P "$server" 2>/dev/null || true; kill "$server" 2>/dev/null || true; }   # "|| true": set -e is active inside traps too
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP PIPE   # also when the caller closes our output early

for _ in $(seq 1 100); do curl -sf "http://localhost:$port/health" >/dev/null && break; sleep 0.2; done
curl -sf "http://localhost:$port/health" >/dev/null || { echo "$lang did not start:"; cat "$log"; exit 1; }

cd "$root"
BASE_URL="http://localhost:$port" node --test contract/ || { echo "--- $lang server log (tail)"; tail -40 "$log"; exit 1; }
