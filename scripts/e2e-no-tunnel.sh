#!/usr/bin/env bash
# R8 — the owner flow with NO tunnel, against a simulated signerd (nosgx, T0): two directories play
# the two machines. Everything the "server" produces is a file; everything the "laptop" produces is
# a file; the only thing that crosses is a copy (here `cp`, in life `scp`). This script is also the
# source of the commands in docs/FAQ.md setup 1.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
E=${E2E_DIR:-/tmp/tee-signer-e2e-no-tunnel}; rm -rf "$E"; mkdir -p "$E/server/state" "$E/laptop"
SERVER="$E/server"; LAPTOP="$E/laptop"
SD=$ROOT/host/signerd/target/debug/signerd; OC=$ROOT/owner/owner-cli/target/debug/owner-cli
export OWNER_PASSPHRASE=test-passphrase-123
carry() { cp "$1" "$2"; }   # scp in life

echo "== server: the daemon runs; nothing listens beyond its own loopback =="
"$SD" run --state-dir "$SERVER/state" --listen 127.0.0.1:7391 > "$SERVER/signerd.log" 2>&1 &
SDPID=$!; trap 'kill $SDPID 2>/dev/null || true' EXIT; sleep 1.5

echo "== laptop: keys (the private keys never leave this directory) =="
"$OC" keygen --out "$LAPTOP/owner.key" --role owner >/dev/null
"$OC" keygen --out "$LAPTOP/recovery.key" --role recovery >/dev/null
"$OC" pubkey --key "$LAPTOP/owner.key" > "$LAPTOP/owner.pub"
"$OC" pubkey --key "$LAPTOP/recovery.key" > "$LAPTOP/recovery.pub"
carry "$LAPTOP/owner.pub" "$SERVER/owner.pub"; carry "$LAPTOP/recovery.pub" "$SERVER/recovery.pub"

echo "== server: init with the two PUBLIC keys; the answer is a file =="
"$SD" init --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --network regtest \
  --owner-pk-file "$SERVER/owner.pub" --recovery-pk-file "$SERVER/recovery.pub" --out "$SERVER/init-response.json"
carry "$SERVER/init-response.json" "$LAPTOP/init-response.json"

echo "== laptop: verify the answer and write the wallet record; check the recovery blob offline =="
"$OC" init --response "$LAPTOP/init-response.json" --network regtest --owner "$LAPTOP/owner.key" \
  --recovery-pk-file "$LAPTOP/recovery.pub" --out "$LAPTOP/wallet.json" | grep -E "tier|xpub|fingerprint"
"$OC" recovery-verify --wallet "$LAPTOP/wallet.json" --recovery-key "$LAPTOP/recovery.key"

echo "== server: status to a file; laptop: sign the mandate against that file =="
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
carry "$SERVER/status.json" "$LAPTOP/status.json"
FP=$(python3 -c "import json;print(json.load(open('$LAPTOP/wallet.json'))['fingerprint'])")
cat > "$LAPTOP/mandate.json" <<JSON
{ "version": 1, "network": "regtest",
  "wallet": { "fingerprint": "$FP", "account": "84'/1'/0'", "scriptTypes": ["p2wpkh"] },
  "destinations": { "trusted": [], "unlisted": { "maxPerTx": 1000000, "maxPerWindow": 5000000 } },
  "limits": { "maxPerTx": 100000000, "window": { "blocks": 144, "maxOutflow": 500000000 }, "maxFeeAbs": 100000, "maxFeeRate": 100, "maxInputs": 64, "maxOutputs": 32, "ownIndexGap": 100, "maxReorg": 6 },
  "rules": { "sighash": "ALL", "payjoin": "none", "opReturn": "none", "rbf": true },
  "chain": { "checkpoint": { "hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "height": 0, "time": 1296688602, "bits": "207fffff", "periodStartTime": 1296688602, "periodBits": "207fffff" } },
  "freshness": { "required": false, "maxTipLag": 6 },
  "validity": { "notAfterHeight": 100000 }, "timelockBlocks": 144 }
JSON
"$OC" --status-file "$LAPTOP/status.json" --wallet-record "$LAPTOP/wallet.json" --out "$LAPTOP/policy-install.msg" \
  policy-sign --json "$LAPTOP/mandate.json" --key "$LAPTOP/owner.key" | tail -1
carry "$LAPTOP/policy-install.msg" "$SERVER/policy-install.msg"

echo "== server: hand the file to the enclave; the answer is a file =="
"$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/policy-install.msg" --out "$SERVER/policy-install.result.json"
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
python3 -c "import json;d=json.load(open('$SERVER/status.json'))['response'];assert d['installed'] and d['nonce']==0;print('  installed, nonce', d['nonce'], 'boot_armed', d['boot_armed'])"

echo "== server: a restart (a reboot, an update — or a rollback): the enclave is unarmed =="
kill $SDPID; wait $SDPID 2>/dev/null || true
"$SD" run --state-dir "$SERVER/state" --listen 127.0.0.1:7391 >> "$SERVER/signerd.log" 2>&1 &
SDPID=$!; trap 'kill $SDPID 2>/dev/null || true' EXIT; sleep 1.5
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
python3 -c "import json;d=json.load(open('$SERVER/status.json'))['response'];assert d['boot_armed'] is False;print('  boot_armed', d['boot_armed'], 'challenge', d['boot_challenge'][:16]+'…')"
carry "$SERVER/status.json" "$LAPTOP/status.json"

echo "== laptop: approve this start — a signed message over the challenge in the file =="
"$OC" --status-file "$LAPTOP/status.json" --wallet-record "$LAPTOP/wallet.json" --out "$LAPTOP/arm.msg" arm --key "$LAPTOP/owner.key"
carry "$LAPTOP/arm.msg" "$SERVER/arm.msg"

echo "== server: hand it over; the enclave is armed for this load =="
"$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/arm.msg" --out "$SERVER/arm.result.json"
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
python3 -c "import json;d=json.load(open('$SERVER/status.json'))['response'];assert d['boot_armed'] is True and d['nonce']==1;print('  boot_armed', d['boot_armed'], 'nonce', d['nonce'])"

echo "== negative: the same arm file again (a replay within the load) is refused by the nonce =="
if "$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/arm.msg" --out "$SERVER/arm-replay.result.json" >/dev/null 2>&1; then echo "UNEXPECTED: replay accepted"; exit 1; fi
python3 -c "import json;d=json.load(open('$SERVER/arm-replay.result.json'));assert not d['ok'] and 'POLICY_NONCE' in json.dumps(d['response']);print('  refused:', d['response'])"

echo "== negative: a restart, then the OLD arm file (another load's challenge) =="
kill $SDPID; wait $SDPID 2>/dev/null || true
"$SD" run --state-dir "$SERVER/state" --listen 127.0.0.1:7391 >> "$SERVER/signerd.log" 2>&1 &
SDPID=$!; trap 'kill $SDPID 2>/dev/null || true' EXIT; sleep 1.5
if "$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/arm.msg" --out "$SERVER/arm-old.result.json" >/dev/null 2>&1; then echo "UNEXPECTED: old arm accepted"; exit 1; fi
python3 -c "import json;d=json.load(open('$SERVER/arm-old.result.json'));assert not d['ok'];print('  refused:', d['response'])"
echo "== server: freeze right here (no signature); laptop: the signed unfreeze as a file =="
"$SD" freeze --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/freeze.result.json"
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
python3 -c "import json;d=json.load(open('$SERVER/status.json'))['response'];assert d['frozen'] is True;print('  frozen', d['frozen'])"
carry "$SERVER/status.json" "$LAPTOP/status.json"
"$OC" --status-file "$LAPTOP/status.json" --wallet-record "$LAPTOP/wallet.json" --out "$LAPTOP/arm2.msg" arm --key "$LAPTOP/owner.key" >/dev/null
carry "$LAPTOP/arm2.msg" "$SERVER/arm2.msg"
"$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/arm2.msg" --out "$SERVER/arm2.result.json"
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"; carry "$SERVER/status.json" "$LAPTOP/status.json"
"$OC" --status-file "$LAPTOP/status.json" --out "$LAPTOP/unfreeze.msg" unfreeze --key "$LAPTOP/owner.key"
carry "$LAPTOP/unfreeze.msg" "$SERVER/unfreeze.msg"
"$SD" submit --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --file "$SERVER/unfreeze.msg" --out "$SERVER/unfreeze.result.json"
"$SD" status --state-dir "$SERVER/state" --url http://127.0.0.1:7391 --out "$SERVER/status.json"
python3 -c "import json;d=json.load(open('$SERVER/status.json'))['response'];assert d['frozen'] is False and d['boot_armed'] is True;print('  frozen', d['frozen'], 'boot_armed', d['boot_armed'], 'nonce', d['nonce'])"
echo "e2e-no-tunnel: OK"
