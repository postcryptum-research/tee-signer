#!/usr/bin/env bash
# Dev BTCPay stack on the SGX box, docker only, localhost only, no root, no nginx.
#   stack.sh gen      generate Generated/docker-compose.generated.yml (signet, no reverse proxy, no lightning, tee-signer sidecar)
#   stack.sh up|down|ps|logs <svc>
# Owner's constraints (2026-11-03): the BTCPay web part runs only in Docker, bound to 127.0.0.1, nothing in nginx.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${TEE_STACK_DIR:-$HOME/tee-signer-btcpay}
export NBITCOIN_NETWORK=${NBITCOIN_NETWORK:-signet}
export BTCPAYGEN_CRYPTO1=btc
export BTCPAYGEN_REVERSEPROXY=none
export BTCPAYGEN_LIGHTNING=none
export BTCPAYGEN_ADDITIONAL_FRAGMENTS=opt-add-tee-signer.custom
export NOREVERSEPROXY_HTTP_PORT=${NOREVERSEPROXY_HTTP_PORT:-7392}
export BTCPAY_HOST=${BTCPAY_HOST:-127.0.0.1}
export BTCPAY_PROTOCOL=http
export TEE_PLUGIN_DIR=${TEE_PLUGIN_DIR:-$ROOT/plugin}
COMPOSE="$ROOT/btcpayserver-docker/Generated/docker-compose.generated.yml"
cmd=${1:-help}
case "$cmd" in
  gen)
    mkdir -p "$ROOT" "$TEE_PLUGIN_DIR"
    cd "$ROOT"
    [ -d btcpayserver-docker ] || git clone -q --depth 1 https://github.com/btcpayserver/btcpayserver-docker.git
    cd btcpayserver-docker
    cp "$HERE/opt-add-tee-signer.custom.yml" docker-compose-generator/docker-fragments/
    mkdir -p Generated
    docker run --rm -v "$(pwd)/Generated:/app/Generated" \
      -v "$(pwd)/docker-compose-generator/docker-fragments:/app/docker-fragments" \
      -v "$(pwd)/docker-compose-generator/crypto-definitions.json:/app/crypto-definitions.json" \
      -e BTCPAYGEN_CRYPTO1 -e NBITCOIN_NETWORK -e BTCPAYGEN_REVERSEPROXY -e BTCPAYGEN_LIGHTNING -e BTCPAYGEN_ADDITIONAL_FRAGMENTS \
      -e BTCPAYGEN_EXCLUDE_FRAGMENTS="${BTCPAYGEN_EXCLUDE_FRAGMENTS:-btcpay-host}" \
      btcpayserver/docker-compose-generator
    # bind the only published port to localhost
    # the generator writes "${NOREVERSEPROXY_HTTP_PORT:-80}:49392"; bind it to localhost on our reserved port
    sed -i "s#\"\${NOREVERSEPROXY_HTTP_PORT:-80}:49392\"#\"127.0.0.1:${NOREVERSEPROXY_HTTP_PORT}:49392\"#" Generated/docker-compose.generated.yml
    grep -q "127.0.0.1:${NOREVERSEPROXY_HTTP_PORT}:49392" Generated/docker-compose.generated.yml || { echo "FATAL: port binding not localhost"; exit 1; }
    grep -n "ports:" -A 2 Generated/docker-compose.generated.yml | head -20
    echo "generated: $COMPOSE";;
  up)   cd "$ROOT/btcpayserver-docker" && docker compose -f "$COMPOSE" -p tee-btcpay up -d "${@:2}";;
  down) cd "$ROOT/btcpayserver-docker" && docker compose -f "$COMPOSE" -p tee-btcpay down;;
  ps)   docker compose -f "$COMPOSE" -p tee-btcpay ps;;
  logs) shift; docker compose -f "$COMPOSE" -p tee-btcpay logs --tail=100 "$@";;
  *) sed -n 2,6p "$0";;
esac
