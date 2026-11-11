#!/usr/bin/env bash
# Dev BTCPay stack on the SGX box, docker only, localhost only, no root, no nginx.
#   stack.sh gen      generate Generated/docker-compose.generated.yml (signet, no reverse proxy, no lightning, tee-signer sidecar)
#   stack.sh up|down|ps|logs <svc>
#   stack.sh install-plugin   copy the built DLL into BTCPay's plugins volume and restart it
#                             (BTCPAY_DEBUG_PLUGINS only works in DEBUG builds of BTCPay; release images load Plugins/<Id>/<Id>.dll)
# Owner's constraints (2026-11-03): the BTCPay web part runs only in Docker, bound to 127.0.0.1, nothing in nginx.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${TEE_STACK_DIR:-$HOME/tee-signer-btcpay}
export NBITCOIN_NETWORK=${NBITCOIN_NETWORK:-signet}
export BTCPAYGEN_CRYPTO1=btc
export BTCPAYGEN_REVERSEPROXY=none
export BTCPAYGEN_LIGHTNING=none
# T1 (Hetzner, /dev/isgx) or T2 (Azure, in-kernel driver): TEE_FRAGMENT=opt-add-tee-signer-t2.custom
export TEE_FRAGMENT=${TEE_FRAGMENT:-opt-add-tee-signer.custom}
# extra stock fragments, e.g. TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs (prune the node on a small disk)
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="${TEE_EXTRA_FRAGMENTS:+$TEE_EXTRA_FRAGMENTS;}$TEE_FRAGMENT"
export NOREVERSEPROXY_HTTP_PORT=${NOREVERSEPROXY_HTTP_PORT:-7392}
export BTCPAY_HOST=${BTCPAY_HOST:-127.0.0.1}
export BTCPAY_PROTOCOL=http
export TEE_PLUGIN_DIR=${TEE_PLUGIN_DIR:-$ROOT/plugin}
COMPOSE="$ROOT/btcpayserver-docker/Generated/docker-compose.generated.yml"
# bounded container logs for every service (see logging.override.yml)
LOGOVR="$HERE/logging.override.yml"
COMPOSE_FILES=(-f "$COMPOSE" -f "$LOGOVR")
cmd=${1:-help}
case "$cmd" in
  gen)
    mkdir -p "$ROOT" "$TEE_PLUGIN_DIR"
    cd "$ROOT"
    [ -d btcpayserver-docker ] || git clone -q --depth 1 https://github.com/btcpayserver/btcpayserver-docker.git
    cd btcpayserver-docker
    # our fragments (the sidecar for T1/T2, the opt-in TPM overlay); only those named in TEE_FRAGMENT /
    # TEE_EXTRA_FRAGMENTS take part in the generation
    cp "$HERE"/opt-add-tee-signer*.custom.yml docker-compose-generator/docker-fragments/
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
  up)   cd "$ROOT/btcpayserver-docker" && docker compose "${COMPOSE_FILES[@]}" -p tee-btcpay up -d "${@:2}";;
  down) cd "$ROOT/btcpayserver-docker" && docker compose "${COMPOSE_FILES[@]}" -p tee-btcpay down;;
  ps)   docker compose "${COMPOSE_FILES[@]}" -p tee-btcpay ps;;
  logs) shift; docker compose "${COMPOSE_FILES[@]}" -p tee-btcpay logs --tail=100 "$@";;
  install-plugin)
    docker exec generated_btcpayserver_1 sh -c "mkdir -p /root/.btcpayserver/Plugins/BTCPayServer.Plugins.TeeSigner"
    docker cp "$TEE_PLUGIN_DIR/BTCPayServer.Plugins.TeeSigner.dll" generated_btcpayserver_1:/root/.btcpayserver/Plugins/BTCPayServer.Plugins.TeeSigner/BTCPayServer.Plugins.TeeSigner.dll
    docker restart generated_btcpayserver_1 >/dev/null; sleep 30
    docker logs --since 1m generated_btcpayserver_1 2>&1 | grep -i "Running plugin" | sed 's/^.*PluginManager: //';;
  *) sed -n 2,6p "$0";;
esac
