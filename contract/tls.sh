#!/usr/bin/env bash
# Checks how each implementation treats DATABASE_URL sslmode against a TLS-only Postgres with a private CA.
#   contract/tls.sh [go rust python nestjs]      (needs docker, openssl, psql; services must be built: make contract-<lang> does that)
# Starts its own Postgres container on 127.0.0.1:5434 and removes it, and its throwaway certificates, on exit.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
langs=("$@"); [ ${#langs[@]} -eq 0 ] && langs=(go rust python nestjs)
C="$(mktemp -d)"; name="boilerplate-pgtls-$$"; fails=0
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$C"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM HUP

# A CA and a server certificate for "localhost" only, with the extensions strict verifiers require.
ca_cnf() { printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=%s\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' "$1"; }
ca_cnf boilerplate-test-ca > "$C/ca.cnf"; ca_cnf some-other-ca > "$C/other.cnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$C/ca.cnf" -keyout "$C/ca.key" -out "$C/ca.crt" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$C/other.cnf" -keyout "$C/other.key" -out "$C/other-ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$C/server.key" -out "$C/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > "$C/leaf.ext"
openssl x509 -req -in "$C/server.csr" -CA "$C/ca.crt" -CAkey "$C/ca.key" -CAcreateserial -days 2 -extfile "$C/leaf.ext" -out "$C/server.crt" 2>/dev/null
printf 'local all all trust\nhostssl all all all scram-sha-256\n' > "$C/pg_hba.conf"   # no plaintext TCP at all
chmod 644 "$C"/*; chmod 755 "$C"

docker run -d --name "$name" -p 127.0.0.1:5434:5432 -e POSTGRES_PASSWORD=postgres -v "$C":/certs:ro postgres:17-alpine sh -c \
  'cp /certs/server.crt /certs/server.key /var/lib/postgresql/ && chown postgres:postgres /var/lib/postgresql/server.* && chmod 600 /var/lib/postgresql/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key -c hba_file=/certs/pg_hba.conf' >/dev/null
admin="postgres://postgres:postgres@localhost:5434/postgres?sslmode=verify-full"
for _ in $(seq 1 60); do PGSSLROOTCERT="$C/ca.crt" psql "$admin" -Atc 'select 1' >/dev/null 2>&1 && break; sleep 0.5; done
for l in "${langs[@]}"; do PGSSLROOTCERT="$C/ca.crt" psql "$admin" -qc "create database boilerplate_$l" || exit 1; done

check() { # lang port migrate-command start...
  local lang=$1 port=$2 mig=$3; shift 3; local start=("$@")
  local envs=(PATH="$PATH" HOME="$HOME" PORT=$port APP_ENV=development APP_URL=http://localhost:3000 JWT_SECRET=tls-check-secret-0123456789abcdefgh
    CORS_ORIGINS=http://localhost:3000 SMTP_HOST=localhost SMTP_PORT=1025 S3_ENDPOINT=http://localhost:9000 S3_REGION=auto S3_BUCKET=boilerplate
    S3_ACCESS_KEY_ID=minioadmin S3_SECRET_ACCESS_KEY=minioadmin)
  local L="postgres://postgres:postgres@localhost:5434/boilerplate_$lang" I="postgres://postgres:postgres@127.0.0.1:5434/boilerplate_$lang"
  echo "== $lang"
  if (cd "$root/$lang" && env -i "${envs[@]}" DATABASE_URL="$L?sslmode=verify-full&sslrootcert=$C/ca.crt" bash -c "$mig") >/dev/null 2>&1
  then echo "  ok    migrate with verify-full + CA"; else echo "  FAIL  migrate with verify-full + CA"; fails=$((fails+1)); fi
  try() { # label expect url
    local log; log="$(mktemp)"
    ( cd "$root/$lang" && exec env -i "${envs[@]}" DATABASE_URL="$3" "${start[@]}" ) >"$log" 2>&1 &
    local p=$! code=000
    for _ in $(seq 1 40); do code=$(curl -s -o /dev/null -w '%{http_code}' "localhost:$port/health/ready" 2>/dev/null); [ "$code" = 200 ] && break; kill -0 $p 2>/dev/null || break; sleep 0.25; done
    local tls; tls=$(PGSSLROOTCERT="$C/ca.crt" psql "$admin" -Atc "select count(*) filter (where s.ssl) from pg_stat_activity a join pg_stat_ssl s using (pid) where a.datname='boilerplate_$lang'" 2>/dev/null)
    local got=REFUSED; [ "$code" = 200 ] && [ "${tls:-0}" -ge 1 ] && got=CONNECTED
    if [ "$got" = "$2" ]; then echo "  ok    $1 -> $got"; else echo "  FAIL  $1 -> expected $2, got $got (ready=$code, tls connections=${tls:-?})"; fails=$((fails+1)); fi
    pkill -P $p 2>/dev/null || true; kill $p 2>/dev/null || true; wait $p 2>/dev/null || true; rm -f "$log"
  }
  try "sslmode=disable against a TLS-only server"      REFUSED   "$L?sslmode=disable"
  try "sslmode=require"                                CONNECTED "$L?sslmode=require"
  try "verify-full, correct CA"                        CONNECTED "$L?sslmode=verify-full&sslrootcert=$C/ca.crt"
  try "verify-full, wrong CA"                          REFUSED   "$L?sslmode=verify-full&sslrootcert=$C/other-ca.crt"
  try "verify-full, no CA (system trust store)"        REFUSED   "$L?sslmode=verify-full"
  try "verify-full, correct CA, host name mismatch"    REFUSED   "$I?sslmode=verify-full&sslrootcert=$C/ca.crt"
  try "verify-ca, correct CA, host name mismatch"      CONNECTED "$I?sslmode=verify-ca&sslrootcert=$C/ca.crt"
  try "verify-ca, wrong CA"                            REFUSED   "$L?sslmode=verify-ca&sslrootcert=$C/other-ca.crt"
}
for l in "${langs[@]}"; do case "$l" in
  go)     check go 8081 "bin/api migrate up" bin/api ;;
  rust)   check rust 8082 "target/debug/boilerplate migrate" target/debug/boilerplate serve ;;
  python) check python 8083 "uv run alembic upgrade head" uv run python -m app ;;
  nestjs) check nestjs 8084 "pnpm exec prisma migrate deploy" node dist/main.js ;;
  *) echo "unknown implementation: $l" >&2; exit 2 ;;
esac; done
echo; [ "$fails" -eq 0 ] && echo "all TLS checks passed" || { echo "$fails TLS check(s) failed"; exit 1; }
