#!/usr/bin/env bash
# R6 scenario 2 — the owner key on a YubiKey PIV slot, exercised against a LAPTOP signerd (T0:
# in-process rcore, no SGX, regtest; mechanics evidence only — the enclave code that verifies the
# 64-byte signature is the same rcore that runs at T1/T2). Run this in YOUR OWN terminal: every
# signature asks for the PIN (typed, never stored) and waits for a touch on the key.
#
#   scripts/piv-scenario.sh start        start the T0 signerd on 127.0.0.1:7391, state in .local/t0-piv/
#   scripts/piv-scenario.sh init         init a throwaway wallet with the YubiKey key as OWNER (no PIN needed)
#   scripts/piv-scenario.sh sign         install the mandate, then tighten it — two signatures on the YubiKey
#   scripts/piv-scenario.sh refuse-file  a keyfile owner signs the same mandate — the enclave must refuse
#   scripts/piv-scenario.sh wrong-pin    type a WRONG PIN once (costs 1 of 3 tries; the next correct PIN resets them)
#   scripts/piv-scenario.sh status | stop
#
# PIV=piv:9a (default) or piv:9a@<serial>; the slot must be PIN ALWAYS + touch ALWAYS (owner-cli refuses otherwise).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${T0_DIR:-$ROOT/.local/t0-piv}
PIV=${PIV:-piv:9a}
SD=$ROOT/host/signerd/target/debug/signerd
OC=$ROOT/owner/owner-cli/target/debug/owner-cli
export SIGNERD_URL=http://127.0.0.1:7391 SIGNERD_TOKEN_FILE=$S/state/token
# throwaway keyfiles only (recovery + a keyfile "owner" that must be refused); the PIN is NOT read from here
export OWNER_PASSPHRASE=t0-piv-throwaway-2026-11-04
EV=$S/evidence.log
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$EV"; }
run() { log "\$ $*"; "$@" 2>&1 | tee -a "$EV"; return "${PIPESTATUS[0]}"; }
st() { "$OC" status | python3 -c "import json,sys;d=json.load(sys.stdin);print('  status:', {k:d.get(k) for k in ['tier','installed','nonce','seq','frozen','best_height','pending']})" | tee -a "$EV"; }
case "${1:-help}" in
  start)
    mkdir -p "$S/state"
    [ -x "$SD" ] || { echo "build first: (cd host/signerd && cargo build --features nosgx)"; exit 1; }
    [ -x "$OC" ] || { echo "build first: (cd owner/owner-cli && cargo build)"; exit 1; }
    if [ -f "$S/signerd.pid" ] && kill -0 "$(cat "$S/signerd.pid")" 2>/dev/null; then echo "already running (pid $(cat "$S/signerd.pid"))"; exit 0; fi
    nohup "$SD" run --state-dir "$S/state" --listen 127.0.0.1:7391 > "$S/signerd.log" 2>&1 &
    echo $! > "$S/signerd.pid"; sleep 1.5
    log "T0 signerd started pid $(cat "$S/signerd.pid") on 127.0.0.1:7391 (nosgx, regtest)"; st;;
  init)
    log "owner key = $PIV (public key read from the slot's metadata; no PIN for this)"
    OPK=$(run "$OC" pubkey --key "$PIV" | tail -1)
    [ -f "$S/recovery.key" ] || "$OC" keygen --out "$S/recovery.key" --role recovery >/dev/null
    [ -f "$S/file-owner.key" ] || "$OC" keygen --out "$S/file-owner.key" --role owner >/dev/null
    RPK=$("$OC" pubkey --key "$S/recovery.key")
    run "$OC" init --network regtest --owner-pk "$OPK" --recovery-pk "$RPK" --out "$S/wallet.json" | grep -E "tier|xpub|fingerprint|TOFU" || true
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
    python3 - <<PY
import json;d=json.load(open('$S/mandate.json'));d['destinations']['unlisted']['maxPerTx']=500000;json.dump(d,open('$S/mandate-tighten.json','w'))
PY
    log "wallet owner_pk = $OPK"; st;;
  sign)
    log "--- install the mandate: PIN + touch #1 on the YubiKey ($PIV) ---"
    run "$OC" policy-sign --json "$S/mandate.json" --key "$PIV" | tail -3; st
    log "--- tighten it: PIN + touch #2 ---"
    run "$OC" policy-sign --json "$S/mandate-tighten.json" --key "$PIV" | tail -3; st;;
  refuse-file)
    log "--- a keyfile owner signs the mandate: the enclave must REFUSE (owner is the YubiKey key) ---"
    if run "$OC" policy-sign --json "$S/mandate.json" --key "$S/file-owner.key" | tail -3; then log "UNEXPECTED: accepted"; exit 1; else log "refused as expected (exit $?)"; fi; st;;
  wrong-pin)
    log "--- type a WRONG PIN on purpose (1 of 3 tries; run 'sign' with the correct PIN right after to reset them) ---"
    if run "$OC" policy-sign --json "$S/mandate.json" --key "$PIV" | tail -3; then log "UNEXPECTED: signed"; exit 1; else log "refused as expected (exit $?)"; fi
    ykman piv info 2>/dev/null | grep -E "PIN tries" | tee -a "$EV";;
  status) st;;
  stop)
    if [ -f "$S/signerd.pid" ]; then kill "$(cat "$S/signerd.pid")" 2>/dev/null || true; rm -f "$S/signerd.pid"; log "T0 signerd stopped"; fi;;
  *) sed -n 2,13p "$0";;
esac
