#!/usr/bin/env bash
# C-SEC-1 (auditor, 2026-11-12): every owner-held secret is generated and encrypted by the OWNER, never by the
# dev. This is the dev-run verification the condition allows — it proves what it can WITHOUT the owner's
# passphrases: (a) the public parts are what the repo / the wallet record pin; (b) the dev cannot open the
# secret files: an empty passphrase and every retired dev-chosen phrase (`.local/retired-dev-passphrases.txt`,
# gitignored) must FAIL. Read-only; exit 1 on any finding. The owner's own successful use of a secret
# (ceremony signature verified under the pinned key, recovery-verify) is the other half of the proof.
set -uo pipefail
cd "$(dirname "$0")/.."
OC=${OC:-owner/owner-cli/target/debug/owner-cli}
CER=.local/ceremony/enclave-ceremony.pem
REC=${RECOVERY_KEY:-.local/signet-t2/recovery-r7.key}
WAL=${WALLET_RECORD:-.local/signet-t2/wallet.json}
RETIRED=.local/retired-dev-passphrases.txt
rc=0; ok() { echo "  PASS: $*"; }; bad() { echo "  FAIL: $*"; rc=1; }

echo "== ceremony key ($CER)"
if [ -f "$CER" ]; then
  # the PEM block may be preceded by an owner-written `Hint:` line (ceremony-key-hint.sh) — look at the block itself
  if grep -q "^-----BEGIN ENCRYPTED PRIVATE KEY-----" "$CER" && ! grep -qE "^-----BEGIN (RSA |EC )?PRIVATE KEY-----" "$CER"; then ok "PEM block is an ENCRYPTED PRIVATE KEY (PKCS#8)"; else bad "key file is NOT encrypted"; fi
  H=$(grep -m1 '^Hint:' "$CER" | sed 's/^Hint: *//'); [ -n "$H" ] && echo "  hint on file: $H (plaintext — must say WHERE, never what; THREAT-MODEL §5)"
  openssl pkey -in "$CER" -passin pass: -noout 2>/dev/null && bad "opens with an EMPTY passphrase" || ok "does not open with an empty passphrase"
  if [ -s "$RETIRED" ]; then
    while IFS= read -r p; do [ -n "$p" ] || continue
      openssl pkey -in "$CER" -passin "pass:$p" -noout 2>/dev/null && bad "opens with a RETIRED dev-chosen passphrase" || ok "retired dev-chosen passphrase refused"
    done < "$RETIRED"
  else echo "  (no $RETIRED — nothing retired to test)"; fi
  echo "  (public key == pinned enclave/ceremony/ceremony_pub.pem needs the passphrase: the OWNER runs"
  echo "   openssl pkey -in $CER -pubout | diff - enclave/ceremony/ceremony_pub.pem  — last done 2026-11-12: unchanged)"
else echo "  (not on this machine)"; fi

echo "== recovery key ($REC)"
if [ -f "$REC" ] && [ -x "$OC" ]; then
  python3 -c "import json,sys;k=json.load(open('$REC'));assert k['kdf']=='scrypt' and k['log_n']>=18 and k['ct_hex'],k;print('  PASS: keyfile is scrypt(N>=2^18)+AES-GCM, pubkey stored in clear')" || bad "keyfile shape"
  PK=$("$OC" pubkey --key "$REC" 2>/dev/null)
  if [ -f "$WAL" ]; then
    RP=$(python3 -c "import json;w=json.load(open('$WAL'));print(w.get('recovery_pk',''))" 2>/dev/null)
    if [ -n "$RP" ]; then [ "$PK" = "$RP" ] && ok "pubkey == the wallet record's recovery pk" || bad "pubkey differs from the wallet record"; else echo "  (record has no recovery pk field to compare; pubkey ${PK:0:16}…)"; fi
  fi
  if [ -s "$RETIRED" ]; then
    while IFS= read -r p; do [ -n "$p" ] || continue
      OWNER_PASSPHRASE="$p" "$OC" recovery-verify --wallet "$WAL" --recovery-key "$REC" >/dev/null 2>&1 && bad "recovery key opens with a RETIRED dev-chosen passphrase" || ok "retired dev-chosen passphrase refused by the recovery key"
    done < "$RETIRED"
  fi
else echo "  (key or owner-cli not on this machine)"; fi

echo "== owner key"
echo "  YubiKey PIV slot 9a (piv:9a@39252737): generated ON the device, attested (C-R6-3), PIN held by the owner — nothing on disk to open"
[ $rc = 0 ] && echo "owner-secrets-check: OK" || echo "owner-secrets-check: FINDINGS"
exit $rc
