#!/usr/bin/env bash
#
# End-to-end test for vault-plugin-secrets-netbox.
#
# Builds the plugin, brings up a mock NetBox token API plus both Vault and
# OpenBao, then drives the identical lifecycle against each engine to prove the
# same binary works on both:
#   configure -> rotate admin -> role -> creds -> renew -> revoke.
#
# Select engines with ENGINES (default "vault openbao"), e.g. ENGINES=openbao.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/test/docker-compose.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"
BINARY="vault-plugin-secrets-netbox"

SEED_TOKEN="nbt_admkey.admsecret"
NETBOX_ADDR="http://127.0.0.1:8080"   # mock netbox, from the host
MOUNT="netbox"
ENGINES="${ENGINES:-vault openbao}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

cleanup() { blue "Tearing down containers"; ${COMPOSE} down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { red "FAIL: $*"; exit 1; }

wait_for() {
  local desc="$1"; shift
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "${WAIT_RETRIES:-90}" ] && fail "timed out waiting for ${desc}"
    sleep 2
  done
  green "ready: ${desc}"
}

jq_field() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

run_engine() {
  local engine="$1" container="$2" cli="$3"
  blue "[${engine}] exercising the plugin"
  ex() { ${COMPOSE} exec -T "${container}" "${cli}" "$@"; }

  local sha; sha="$(sha256sum "${ROOT_DIR}/dist/${BINARY}" | awk '{print $1}')"
  ex plugin register -sha256="${sha}" secret "${BINARY}" >/dev/null || true
  ex secrets disable "${MOUNT}" >/dev/null 2>&1 || true
  ex secrets enable -path="${MOUNT}" "${BINARY}" >/dev/null
  green "[${engine}] plugin registered and mounted"

  # The plugin runs inside the engine container, so it reaches netbox by name.
  ex write "${MOUNT}/config" netbox_url="http://netbox:8080" token="${SEED_TOKEN}" tls_skip_verify=true >/dev/null
  green "[${engine}] configured"

  # Reissue the seeded admin token (auto-discovers ids from the v2 key).
  ex write -f "${MOUNT}/config/rotate" >/dev/null
  green "[${engine}] admin token rotated"

  # --- role + dynamic creds (read-only by default) ---
  ex write "${MOUNT}/roles/ipam" netbox_username="svc-terraform-ipam" write_enabled=true ttl=1h max_ttl=24h >/dev/null
  local json lease tok auth
  json="$(ex read -format=json "${MOUNT}/creds/ipam")"
  lease="$(printf '%s' "${json}" | jq_field '["lease_id"]')"
  tok="$(printf '%s' "${json}" | jq_field '["data"]["token"]')"
  auth="$(printf '%s' "${json}" | jq_field '["data"]["authorization"]')"
  [ -n "${tok}" ] || fail "[${engine}] dynamic creds returned empty token value"
  case "${auth}" in Bearer\ nbt_*) : ;; *) fail "[${engine}] unexpected authorization: ${auth}" ;; esac
  green "[${engine}] dynamic token issued (lease ${lease})"

  # renew extends the lease (and the NetBox expiry)
  ex lease renew "${lease}" >/dev/null
  green "[${engine}] lease renewed"

  # revoke -> token deleted from netbox (re-reading its creds still works via admin)
  ex lease revoke "${lease}" >/dev/null
  green "[${engine}] revoked"

  green "[${engine}] PASSED"
}

blue "Building plugin for linux/amd64"
OS=linux ARCH=amd64 PLUGIN_DIR="${ROOT_DIR}/dist" make -C "${ROOT_DIR}" build

blue "Starting Docker stack (netbox + vault + openbao)"
${COMPOSE} up -d --build

wait_for "netbox" curl -fsS "${NETBOX_ADDR}/healthz"

for engine in ${ENGINES}; do
  case "${engine}" in
    vault)   wait_for "vault"   ${COMPOSE} exec -T vault   vault status -address=http://127.0.0.1:8200; run_engine vault vault vault ;;
    openbao) wait_for "openbao" ${COMPOSE} exec -T openbao bao   status -address=http://127.0.0.1:8200; run_engine openbao openbao bao ;;
    *) fail "unknown engine: ${engine}" ;;
  esac
done

green "ALL END-TO-END CHECKS PASSED (${ENGINES})"
