#!/usr/bin/env bash
# REQ-r9, the `tss` transport against a REAL local TPM (a laptop's PTT/dTPM or a VM's vTPM), nosgx
# daemon: tpm-setup at explicit handles (refusals for occupied ones), anchor from an attested
# certify, counter follows the seals, unattended restart auto-arms, a rolled-back state is
# STATE_STALE, re-anchor, tpm-teardown by the explicit handles — and the TPM's handle lists are
# bit-for-bit what they were before (nothing of anyone else's touched, nothing of ours left).
#
# Needs: /dev/tpmrm0 (group tss), tpm2-tools (for the before/after snapshots only),
#   (cd host/signerd && cargo build --features nosgx,tss) and (cd owner/owner-cli && cargo build).
# Handles: TSS_AK (default 0x81000200) and TSS_NV (default 0x01800200) must be FREE on this TPM —
#   the script refuses to run otherwise (it never evicts). Pick others with these two variables.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=${E2E_DIR:-/tmp/tee-signer-e2e-tss}; rm -rf "$S"; mkdir -p "$S/state"
SD=$ROOT/host/signerd/target/debug/signerd; OC=$ROOT/owner/owner-cli/target/debug/owner-cli
AK=${TSS_AK:-0x81000200}; NV=${TSS_NV:-0x01800200}; TCTI=${TSS_TCTI:-device:/dev/tpmrm0}
[ -x "$SD" ] || { echo "build first: (cd host/signerd && cargo build --features nosgx,tss)"; exit 1; }
[ -x "$OC" ] || { echo "build first: (cd owner/owner-cli && cargo build)"; exit 1; }
[ -w /dev/tpmrm0 ] || { echo "no writable /dev/tpmrm0 (group tss?)"; exit 1; }
unset SIGNERD_TPM_AUTH   # the isolated-test configuration: empty auth (a shared TPM sets it)

echo "=== before: the TPM's persistent handles and NV indices (must be unchanged at the end) ==="
tpm2_getcap handles-persistent > "$S/handles-before.txt"; tpm2_getcap handles-nv-index >> "$S/handles-before.txt"
# tpm2_getcap prints 0x1800200 (no leading zeros); normalise both sides for the occupancy check
norm() { printf '0x%x' "$1"; }
if grep -qi "^- $(norm "$AK")$" "$S/handles-before.txt" || grep -qi "^- $(norm "$NV")$" "$S/handles-before.txt"; then
  echo "REFUSING to run: $AK or $NV is already in use on this TPM — set TSS_AK/TSS_NV to free handles"; exit 1
fi
tr '\n' ' ' < "$S/handles-before.txt"; echo

SDPID=
cleanup() {
  [ -n "$SDPID" ] && { kill "$SDPID" 2>/dev/null || true; wait "$SDPID" 2>/dev/null || true; }
  echo "--- teardown by the explicit handles ---"
  "$SD" tpm-teardown --tcti "$TCTI" --ak-handle "$AK" --nv-index "$NV" --setup-file "$S/tpm-setup.json" 2>/dev/null || echo "TEARDOWN FAILED — remove by hand: tpm2_nvundefine $NV; tpm2_evictcontrol -C o -c $AK"
  tpm2_getcap handles-persistent > "$S/handles-after.txt"; tpm2_getcap handles-nv-index >> "$S/handles-after.txt"
  if diff -u "$S/handles-before.txt" "$S/handles-after.txt" >/dev/null; then echo "  TPM handle lists: identical to before ✓"; else echo "  TPM HANDLE LISTS DIFFER:"; diff -u "$S/handles-before.txt" "$S/handles-after.txt" || true; exit 1; fi
}
trap cleanup EXIT

echo "=== tpm-setup: refusals first (nothing is created by a refused call) ==="
if out=$("$SD" tpm-setup --tcti "$TCTI" --ak-handle 0x81000100 --nv-index "$NV" --out "$S/never.json" 2>&1); then echo "UNEXPECTED: setup on an OCCUPIED ak handle accepted: $out"; exit 1; fi
case "$out" in *REFUSED*"already in use"*) echo "  occupied ak handle (0x81000100 = the owner's key on this laptop) → refused ✓";; *) echo "UNEXPECTED: $out"; exit 1;; esac
if out=$("$SD" tpm-setup --tcti "$TCTI" --ak-handle "$AK" --nv-index 0x01c00002 --out "$S/never.json" 2>&1); then echo "UNEXPECTED: setup on an OCCUPIED nv index accepted: $out"; exit 1; fi
case "$out" in *REFUSED*"already defined"*) echo "  occupied nv index (0x01c00002 = the EK certificate) → refused ✓";; *) echo "UNEXPECTED: $out"; exit 1;; esac
tpm2_getcap handles-persistent > "$S/h.txt"; tpm2_getcap handles-nv-index >> "$S/h.txt"; diff -q "$S/handles-before.txt" "$S/h.txt" >/dev/null && echo "  refusals created nothing ✓"
echo "=== tpm-setup at $AK / $NV ==="
"$SD" tpm-setup --tcti "$TCTI" --ak-handle "$AK" --nv-index "$NV" --out "$S/tpm-setup.json" 2>/dev/null
# a new counter index does not start at 0: the TPM seeds it above the last value of any counter ever
# deleted on it (monotonic across define/undefine, TPM 2.0 part 1) — only equality with the sealed
# expectation ever matters, the absolute value is opaque
python3 -c "import json;d=json.load(open('$S/tpm-setup.json'));assert d['counter']>=1 and len(d['ak_pk_hex'])==130 and len(d['nv_name_hex'])==68, d;print('  created:', {k:(v[:20]+'…' if isinstance(v,str) and len(v)>24 else v) for k,v in d.items()})"
if out=$("$SD" tpm-setup --tcti "$TCTI" --ak-handle "$AK" --nv-index "$NV" --out "$S/never.json" 2>&1); then echo "UNEXPECTED: a second setup on our own handles accepted: $out"; exit 1; fi
[ ! -e "$S/never.json" ] || { echo "UNEXPECTED: a refused setup wrote its --out"; exit 1; }
echo "  a second setup on the same handles → refused (occupied) ✓"
echo "=== teardown resolves its EXACT target (RESP-r9 Q8): a foreign key at the ak handle, a wrong record, no record — all refused, nothing touched ==="
if out=$("$SD" tpm-teardown --tcti "$TCTI" --ak-handle 0x81000100 --nv-index 0x01800201 --setup-file "$S/tpm-setup.json" 2>&1); then echo "UNEXPECTED: teardown of a foreign key accepted: $out"; exit 1; fi
case "$out" in *REFUSED*"public key differs"*) echo "  foreign key (the owner's 0x81000100) → refused: not the recorded key ✓";; *) echo "UNEXPECTED: $out"; exit 1;; esac
python3 -c "import json;d=json.load(open('$S/tpm-setup.json'));d['nv_name_hex']='000b'+'ab'*32;json.dump(d,open('$S/tpm-setup-wrong.json','w'))"
if out=$("$SD" tpm-teardown --tcti "$TCTI" --ak-handle "$AK" --nv-index "$NV" --setup-file "$S/tpm-setup-wrong.json" 2>&1); then echo "UNEXPECTED: teardown with a wrong record accepted: $out"; exit 1; fi
case "$out" in *REFUSED*"its Name differs"*) echo "  our handles but a record naming another index → refused ✓";; *) echo "UNEXPECTED: $out"; exit 1;; esac
if out=$("$SD" tpm-teardown --tcti "$TCTI" --ak-handle "$AK" --nv-index "$NV" --setup-file "$S/does-not-exist.json" 2>&1); then echo "UNEXPECTED: teardown without a record accepted: $out"; exit 1; fi
echo "  no record file → refused ✓"
tpm2_getcap handles-persistent > "$S/h2.txt"; tpm2_getcap handles-nv-index >> "$S/h2.txt"
grep -qi "^- $(norm "$AK")$" "$S/h2.txt" && grep -qi "^- $(norm "$NV")$" "$S/h2.txt" && echo "  our two objects still there ✓"

echo "=== the daemon with SIGNERD_TPM=tss:… from the first start ==="
export SIGNERD_TPM="tss:$TCTI?ak=$AK&nv=$NV"
"$SD" run --state-dir "$S/state" --listen 127.0.0.1:7393 > "$S/signerd.log" 2>&1 &
SDPID=$!; sleep 1.5
export SIGNERD_URL=http://127.0.0.1:7393 SIGNERD_TOKEN_FILE=$S/state/token OWNER_PASSPHRASE=test-passphrase-123
"$OC" keygen --out "$S/owner.key" --role owner >/dev/null; "$OC" keygen --out "$S/recovery.key" --role recovery >/dev/null
RPK=$("$OC" pubkey --key "$S/recovery.key")
"$OC" init --network regtest --owner "$S/owner.key" --recovery-pk "$RPK" --out "$S/wallet.json" | grep -E "tier|fingerprint"
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
"$OC" policy-sign --json "$S/mandate.json" --key "$S/owner.key" | tail -1
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); assert d['tpm_bound'] is False and d['tpm_transport'].startswith('tss:'), d
print('  installed, unanchored:', {k:d[k] for k in ['installed','tpm_bound','tpm_transport']})"

echo "--- the owner anchors from an ATTESTED certify over the owner's nonce (C-R9-D; a real TPMS_ATTEST through the fixed-layout parser) ---"
"$SD" tpm-info --state-dir "$S/state" --url http://127.0.0.1:7393 --out "$S/tpm-info.json"
openssl rand -hex 32 > "$S/anchor-nonce.txt"
"$SD" tpm-certify --state-dir "$S/state" --url http://127.0.0.1:7393 --nonce-file "$S/anchor-nonce.txt" --out "$S/anchor-proof.json"
python3 -c "import json;d=json.load(open('$S/anchor-proof.json'))['response'];print('  real TPMS_ATTEST:', len(d['attest_hex'])//2, 'bytes (magic', d['attest_hex'][:8], 'type', d['attest_hex'][8:12] + '), sig', len(d['sig_hex'])//2, 'bytes')"
"$OC" --wallet-record "$S/wallet.json" anchor --key "$S/owner.key" --tpm-info-file "$S/tpm-info.json" --proof-file "$S/anchor-proof.json" --proof-nonce-file "$S/anchor-nonce.txt" | grep -E "attested counter|anchored"
C0=$(python3 -c "import json;print(json.load(open('$S/tpm-info.json'))['response']['counter'])")
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); assert d['tpm_bound'] is True and d['tpm_expected'] == $C0 + 1, d
print('  anchored:', {k:d[k] for k in ['tpm_bound','tpm_expected','tpm_last_fresh','boot_armed']})"
echo "--- every seal: nonce → NV_Certify → deposit → call, then NV_Increment; the TPM's counter equals the blob's expectation ---"
"$OC" freeze >/dev/null; "$OC" unfreeze --key "$S/owner.key" >/dev/null
"$SD" tpm-info --state-dir "$S/state" --url http://127.0.0.1:7393 --out "$S/tpm-info2.json"
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); t=json.load(open('$S/tpm-info2.json'))['response']
assert d['tpm_expected'] == $C0 + 3 and d['tpm_last_fresh'] is True and t['counter'] == d['tpm_expected'], (d, t)
print('  after freeze+unfreeze: expected', d['tpm_expected'], '== TPM counter', t['counter'], '✓')"
echo "--- an UNATTENDED restart: the fresh counter arms the load, no owner ---"
kill $SDPID; wait $SDPID 2>/dev/null || true
"$SD" run --state-dir "$S/state" --listen 127.0.0.1:7393 >> "$S/signerd.log" 2>&1 &
SDPID=$!; sleep 1.5
"$OC" status | python3 -c "import json,sys;d=json.load(sys.stdin); assert d['boot_armed'] is False; print('  after restart: boot_armed', d['boot_armed'])"
"$OC" freeze >/dev/null
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); assert d['boot_armed'] is True and d['tpm_last_fresh'] is True and d['frozen'] is True, d
print('  after one fresh call:', {k:d[k] for k in ['boot_armed','tpm_last_fresh','tpm_expected']})"
"$OC" unfreeze --key "$S/owner.key" >/dev/null
echo "--- the ROLLBACK: an older state file restored, restart — STATE_STALE against the real counter, no auto-arm ---"
cp "$S/state/state.sealed" "$S/state.sealed.old"
"$OC" freeze >/dev/null; "$OC" unfreeze --key "$S/owner.key" >/dev/null
kill $SDPID; wait $SDPID 2>/dev/null || true
cp "$S/state.sealed.old" "$S/state/state.sealed"
"$SD" run --state-dir "$S/state" --listen 127.0.0.1:7393 >> "$S/signerd.log" 2>&1 &
SDPID=$!; sleep 1.5
if out=$("$OC" freeze 2>&1); then echo "UNEXPECTED: a rolled-back state was accepted: $out"; exit 1; fi
case "$out" in *STATE_STALE*) echo "  refused: STATE_STALE ✓";; *) echo "UNEXPECTED: $out"; exit 1;; esac
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); assert d['boot_armed'] is False and d['tpm_last_fresh'] is False, d
print('  rolled back:', {k:d[k] for k in ['boot_armed','tpm_last_fresh','tpm_expected']})"
echo "--- the owner re-anchors (attended override) ---"
openssl rand -hex 32 > "$S/anchor-nonce2.txt"
"$SD" tpm-certify --state-dir "$S/state" --url http://127.0.0.1:7393 --nonce-file "$S/anchor-nonce2.txt" --out "$S/anchor-proof2.json"
"$OC" --wallet-record "$S/wallet.json" anchor --key "$S/owner.key" --tpm-info-file "$S/tpm-info.json" --proof-file "$S/anchor-proof2.json" --proof-nonce-file "$S/anchor-nonce2.txt" | grep -E "attested counter|anchored"
"$OC" status | python3 -c "
import json,sys;d=json.load(sys.stdin); assert d['boot_armed'] is True and d['tpm_bound'] is True, d; print('  re-anchored:', {k:d[k] for k in ['boot_armed','tpm_expected']})"
"$OC" freeze >/dev/null; "$OC" unfreeze --key "$S/owner.key" >/dev/null
echo "e2e-tss-local: OK (REQ-r9 against a real TPM; proofs: $S)"
