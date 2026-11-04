#!/usr/bin/env bash
# Owner flow end to end against a simulated signerd (nosgx): keys, init, recovery check, install,
# tighten (applies), loosen (pending) + cancel by the recovery key, freeze/unfreeze.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${E2E_DIR:-/tmp/tee-signer-e2e-local}; rm -rf "$S"; mkdir -p "$S/state"
SD=$ROOT/host/signerd/target/debug/signerd; OC=$ROOT/owner/owner-cli/target/debug/owner-cli
"$SD" run --state-dir "$S/state" --listen 127.0.0.1:7391 > "$S/signerd.log" 2>&1 &
SDPID=$!; trap 'kill $SDPID 2>/dev/null || true' EXIT; sleep 1.5
export SIGNERD_URL=http://127.0.0.1:7391 SIGNERD_TOKEN_FILE=$S/state/token OWNER_PASSPHRASE=test-passphrase-123
"$OC" keygen --out "$S/owner.key" --role owner >/dev/null; "$OC" keygen --out "$S/recovery.key" --role recovery >/dev/null
OPK=$("$OC" pubkey --key "$S/owner.key"); RPK=$("$OC" pubkey --key "$S/recovery.key")
"$OC" init --network regtest --owner "$S/owner.key" --recovery-pk "$RPK" --out "$S/wallet.json" | grep -E "tier|xpub|fingerprint"
"$OC" recovery-verify --wallet "$S/wallet.json" --recovery-key "$S/recovery.key"
FP=$(python3 -c "import json;print(json.load(open('$S/wallet.json'))['fingerprint'])")
cat > "$S/mandate.json" <<JSON
{ "version": 1, "network": "regtest",
  "wallet": { "fingerprint": "$FP", "account": "84'/1'/0'", "scriptTypes": ["p2wpkh"] },
  "destinations": { "trusted": [], "unlisted": { "maxPerTx": 1000000, "maxPerWindow": 5000000 } },
  "limits": { "maxPerTx": 100000000, "window": { "blocks": 144, "maxOutflow": 500000000 }, "maxFeeAbs": 100000, "maxFeeRate": 100, "maxInputs": 64, "maxOutputs": 32, "ownIndexGap": 100, "maxReorg": 6 },
  "rules": { "sighash": "ALL", "payjoin": "none", "opReturn": "none", "rbf": true },
  "chain": { "checkpoint": { "hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "height": 0, "time": 1296688602, "bits": "207fffff", "periodStartTime": 1296688602, "periodBits": "207fffff" } },
  "freshness": { "required": false, "maxTipLag": 6 },
  "validity": { "notAfterHeight": 100000 }, "timelockBlocks": 144 }
JSON
"$OC" policy-build --json "$S/mandate.json" | grep -E "^  hash"
"$OC" policy-sign --json "$S/mandate.json" --key "$S/owner.key" | tail -1
st() { "$OC" status | python3 -c "import json,sys;d=json.load(sys.stdin);print('  status:', {k:d[k] for k in ['installed','nonce','seq','frozen','best_height','pending']})"; }
st
python3 - <<PY
import json;d=json.load(open('$S/mandate.json'));d['destinations']['unlisted']['maxPerTx']=500000;json.dump(d,open('$S/mandate2.json','w'))
d=json.load(open('$S/mandate.json'));d['destinations']['unlisted']['maxPerTx']=2000000;json.dump(d,open('$S/mandate3.json','w'))
PY
echo "--- tighten ---"; "$OC" policy-show --json "$S/mandate2.json" | grep -E "DIFF|classification"; "$OC" policy-sign --json "$S/mandate2.json" --key "$S/owner.key" | tail -1; st
echo "--- loosen (pending) then cancel with the RECOVERY key ---"; "$OC" policy-sign --json "$S/mandate3.json" --key "$S/owner.key" | tail -1; st; "$OC" cancel --key "$S/recovery.key"; st
echo "--- freeze (unauthenticated) / unfreeze (owner) ---"; "$OC" freeze; st; "$OC" unfreeze --key "$S/owner.key"; st
echo "--- REQ-r7: a loosening pending, the signer frozen, then a RESTART = a pause until the owner arms this load ---"
"$OC" policy-sign --json "$S/mandate3.json" --key "$S/owner.key" | tail -1; st
PENDING_BEFORE=$("$OC" status 2>/dev/null | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['pending']))")
"$OC" freeze >/dev/null
kill $SDPID; wait $SDPID 2>/dev/null || true
"$SD" run --state-dir "$S/state" --listen 127.0.0.1:7391 >> "$S/signerd.log" 2>&1 &
SDPID=$!; trap 'kill $SDPID 2>/dev/null || true' EXIT; sleep 1.5
"$OC" status 2>/dev/null | python3 -c "
import json,sys;d=json.load(sys.stdin)
assert d['boot_armed'] is False, 'a restarted enclave must be unarmed'
assert d['frozen'] is True, 'a freeze taken before the restart persists'
assert json.dumps(d['pending']) == '$PENDING_BEFORE', 'a pending loosening keeps its activation height across the restart'
assert d['auto_arm'] is False
print('  after restart:', {k:d[k] for k in ['boot_armed','frozen','pending','seq','nonce']})"
echo "--- the owner arms this load (the record on this machine: last_seen_seq $(python3 -c "import json;print(json.load(open('$S/wallet.json')).get('last_seen_seq'))")) ---"
"$OC" --wallet-record "$S/wallet.json" arm --key "$S/owner.key"
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin)
assert d['boot_armed'] is True
assert d['frozen'] is True, 'arming does not unfreeze'
assert json.dumps(d['pending']) == '$PENDING_BEFORE', 'arming does not accelerate a pending loosening'
print('  after arm:', {k:d[k] for k in ['boot_armed','frozen','pending','seq','nonce']})"
echo "--- a second arm for the same load is refused (the nonce was spent; nothing to do) ---"
if out=$("$OC" --wallet-record "$S/wallet.json" arm --key "$S/owner.key" 2>&1); then echo "UNEXPECTED: second arm accepted: $out"; exit 1; fi
case "$out" in *"already armed"*) echo "  refused: already armed";; *) echo "UNEXPECTED: $out"; exit 1;; esac
"$OC" unfreeze --key "$S/owner.key"; "$OC" cancel --key "$S/recovery.key"; st
echo "e2e-local: OK"
