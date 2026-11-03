#!/usr/bin/env bash
# Run ON the SGX box: restart the dev signerd (own user, own dir, own port; no sudo, no systemd).
set -euo pipefail
source /opt/intel/sgxsdk/environment
ST=$HOME/tee-signer-state; mkdir -p "$ST"
cd "$HOME/tee-signer/host/signerd"
if [ -f "$ST/pid" ] && kill -0 "$(cat "$ST/pid")" 2>/dev/null; then kill "$(cat "$ST/pid")"; sleep 1; fi
nohup ./target/release/signerd --enclave "$HOME/tee-signer/enclave/enclave.signed.so" run \
  --state-dir "$ST" --listen 127.0.0.1:7390 \
  --bitcoind-rpc http://127.0.0.1:10810 --bitcoind-cookie "$HOME/trust-bridge/btc-signet/signet/.cookie" \
  --headers-interval 20 > "$ST/signerd.log" 2>&1 &
echo $! > "$ST/pid"
echo "signerd pid $(cat "$ST/pid")"
