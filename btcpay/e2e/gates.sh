#!/usr/bin/env bash
# R3 end-to-end on the dev stack (run ON the SGX box). Asserts the auditor's four executable gates:
#  (a) the store wallet is IsHotWallet=false throughout (incl. after a BTCPay restart);
#  (b) nbxv1_metadata holds zero Mnemonic/MasterHDKey/AccountHDKey rows;
#  (c) the four in-process signing sites are inert (Greenfield signWithSeed → 503; no payjoin in
#      the invoice BIP21; the stock payout processor is not configured; the UI path follows (a));
#  (d) the plugin only routes: a payout is paid through the enclave (receipt seq advances) and a
#      frozen signer makes the payout wait with the refusal named, charging nothing.
#   gates.sh setup   admin, API key, store, COLD wallet, plugin settings + processor, gates (a) and (b)
#   gates.sh run     gates (c) and (d) — needs the stack synced and the wallet's coins indexed
set -euo pipefail
PHASE=${1:-all}
BT=${BTCPAY_URL:-http://127.0.0.1:7392}
SIGNER_TOKEN=$(cat "${SIGNER_TOKEN_FILE:-$HOME/tee-signer-state/token}")
XPUB=${TEE_XPUB:?set TEE_XPUB}; FP=${TEE_FINGERPRINT:?set TEE_FINGERPRINT}
# Payees: BTCPay refuses a second payout to an address already used by another payout
# ("duplicate-destination"), so every payout gets a fresh throwaway P2WPKH outside the wallet
# (random 20-byte program, unspendable: signet coins, labeled as such). PAYEE overrides the first.
throwaway_addr() { python3 - <<'PY'
import os
C="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def pm(v):
    G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for x in v:
        b=c>>25; c=((c&0x1ffffff)<<5)^x
        for i in range(5): c^=G[i] if (b>>i)&1 else 0
    return c
def cb(d,f,t):
    a=0;b=0;r=[];m=(1<<t)-1
    for x in d:
        a=(a<<f)|x; b+=f
        while b>=t: b-=t; r.append((a>>b)&m)
    if b: r.append((a<<(t-b))&m)
    return r
h=[ord(c)>>5 for c in "tb"]+[0]+[ord(c)&31 for c in "tb"]
d=[0]+cb(os.urandom(20),8,5); x=pm(h+d+[0]*6)^1
print("tb1"+"".join(C[v] for v in d+[(x>>5*(5-i))&31 for i in range(6)]))
PY
}
PAYEE=${PAYEE:-$(throwaway_addr)}
EMAIL=admin@tee.local; PASS=${BTCPAY_PASS:-tee-signer-e2e-Passw0rd!}
S=$HOME/tee-signer-btcpay/e2e; mkdir -p "$S"
pass() { echo "  PASS $1"; }; fail() { echo "  FAIL $1"; exit 1; }
j() { python3 -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw); print($1)
except Exception as e:
    print('  j(): cannot read the field from:', raw[:300], file=sys.stderr); sys.exit(1)
"; }

if [ "$PHASE" = "setup" ] || [ "$PHASE" = "all" ]; then
if [ -f "$S/apikey" ] && [ -f "$S/store" ] && curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token $(cat "$S/apikey")" "$BT/api/v1/stores/$(cat "$S/store")" | grep -q 200; then
  echo "== 1-2. reusing the existing admin API key and store ($(cat "$S/store"))"
  KEY=$(cat "$S/apikey"); STORE=$(cat "$S/store"); H=(-H "Authorization: token $KEY" -H 'content-type: application/json')
else
echo "== 1. admin user + API key"
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BT/api/v1/users" -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\",\"isAdministrator\":true}" | sed 's/^/  users: /'
KEY=$(curl -s -u "$EMAIL:$PASS" -X POST "$BT/api/v1/api-keys" -H 'content-type: application/json' -d '{"label":"e2e","permissions":["btcpay.server.canmodifyserversettings","btcpay.store.canmodifystoresettings","btcpay.store.canviewstoresettings","btcpay.store.cancreateinvoice","btcpay.store.canviewinvoices","btcpay.store.canmanagepullpayments","btcpay.store.cancreatepullpayments","btcpay.store.canmanagepayouts","btcpay.store.canviewpayouts","btcpay.store.canmanagewallets","btcpay.store.canviewwallet","btcpay.store.cancreatetransactions","btcpay.store.cansigntransactions","btcpay.store.canbroadcasttransactions"]}' | j "d['apiKey']")
H=(-H "Authorization: token $KEY" -H 'content-type: application/json')
echo "$KEY" > "$S/apikey"

echo "== 2. store + COLD wallet from the enclave xpub"
STORE=$(curl -s "${H[@]}" -X POST "$BT/api/v1/stores" -d '{"name":"tee-signer e2e"}' | j "d['id']"); echo "$STORE" > "$S/store"
curl -s "${H[@]}" -X PUT "$BT/api/v1/stores/$STORE/payment-methods/BTC-CHAIN" -d "{\"enabled\":true,\"config\":\"[$FP/84'/1'/0']$XPUB\"}" | j "d['config']['accountDerivation'][:20]" | sed 's/^/  wallet set: /'
fi
echo "== gate (a): IsHotWallet=false in the store record"
HOT=$(docker exec generated_postgres_1 psql -U postgres -d btcpayserversignet -tAc "select \"DerivationStrategies\" from \"Stores\" where \"Id\"='$STORE'")
echo "$HOT" | grep -qi '"IsHotWallet": *true' && fail "wallet flagged hot" || pass "store wallet is cold ($(echo "$HOT" | grep -o '"IsHotWallet":[^,}]*' || echo 'IsHotWallet absent = false'))"

echo "== 3. plugin: signer settings + processor"
curl -s -w " [%{http_code}]" "${H[@]}" -X PUT "$BT/plugins/teesigner/api/$STORE/settings" -d "{\"signerdUrl\":\"http://tee-signer:7390\",\"token\":\"$SIGNER_TOKEN\",\"minConfirmations\":0,\"fallbackFeeRateSatVb\":5}" | sed 's/^/  settings: /'; echo
curl -s "${H[@]}" "$BT/plugins/teesigner/api/$STORE/status" > "$S/status.json"; python3 - "$S/status.json" <<'PY'
import json,sys;d=json.load(open(sys.argv[1]));e=d.get('enclave') or {}
print("  enclave:", {k:e.get(k) for k in ['tier','installed','bestHeight','seq','xpub']}, "xpubMatches:", d.get('xpubMatches'), "walletIsHot:", d.get('walletIsHot'), "error:", d.get('error'))
assert d.get('xpubMatches') is True, "xpub mismatch"
assert d.get('walletIsHot') is False, "hot"
PY
pass "enclave xpub matches the store wallet"
curl -s -w " [%{http_code}]" "${H[@]}" -X POST "$BT/plugins/teesigner/api/$STORE/processor?enable=true" | sed 's/^/  processor: /'; echo

echo "== gate (b): no key material in nbxv1_metadata"
N=$(docker exec generated_postgres_1 psql -U postgres -d nbxplorersignet -tAc "select count(*) from nbxv1_metadata where key in ('Mnemonic','MasterHDKey','AccountHDKey')")
[ "$N" = "0" ] && pass "nbxv1_metadata key rows = 0" || fail "nbxv1_metadata has $N key rows"
fi
if [ "$PHASE" = "run" ] || [ "$PHASE" = "all" ]; then
KEY=$(cat "$S/apikey"); STORE=$(cat "$S/store"); H=(-H "Authorization: token $KEY" -H 'content-type: application/json')

echo "== gate (c): the four in-process signing sites are inert"
CODE=$(curl -s -o "$S/s2.json" -w "%{http_code}" "${H[@]}" -X POST "$BT/api/v1/stores/$STORE/payment-methods/BTC-CHAIN/wallet/transactions" -d "{\"destinations\":[{\"destination\":\"$PAYEE\",\"amount\":\"0.00001\"}],\"feeRate\":2,\"signWithSeed\":true,\"proceedWithBroadcast\":false}")
[ "$CODE" = "503" ] && pass "S2 Greenfield signWithSeed → 503 ($(cat "$S/s2.json" | head -c 120))" || fail "S2 returned $CODE: $(cat "$S/s2.json" | head -c 200)"
INV=$(curl -s "${H[@]}" -X POST "$BT/api/v1/stores/$STORE/invoices" -d '{"amount":"0.0001","currency":"BTC"}' | j "d['id']")
PM=$(curl -s "${H[@]}" "$BT/api/v1/stores/$STORE/invoices/$INV/payment-methods")
echo "$PM" | grep -q 'pj=' && fail "S4 payjoin advertised" || pass "S4 payjoin not advertised in the invoice BIP21 (cold wallet)"
PROCS=$(docker exec generated_postgres_1 psql -U postgres -d btcpayserversignet -tAc "select \"Processor\" from \"PayoutProcessors\" where \"StoreId\"='$STORE'")
echo "$PROCS" | grep -q OnChainAutomatedPayoutSenderFactory && fail "S3 stock processor configured" || pass "S3 stock hot-wallet processor absent; configured: $(echo $PROCS)"
echo "$PROCS" | grep -q TeeSignerPayoutProcessor || fail "TEE processor not configured"
pass "S1 (UI seed path) follows from (a): HotwalletSafe.TryUnlock returns null for IsHotWallet=false (study §2b)"

echo "== gate (d.1): a payout through the enclave"
SEQ0=$(curl -s -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:7390/v1/status | j "d['seq']"); echo "  enclave seq before: $SEQ0"
PP=$(curl -s "${H[@]}" -X POST "$BT/api/v1/stores/$STORE/pull-payments" -d '{"name":"e2e","amount":"0.0001","currency":"BTC","payoutMethods":["BTC-CHAIN"],"autoApproveClaims":true}' | j "d['id']")
PO=$(curl -s "${H[@]}" -X POST "$BT/api/v1/pull-payments/$PP/payouts" -d "{\"destination\":\"$PAYEE\",\"amount\":\"0.00002\",\"payoutMethodId\":\"BTC-CHAIN\"}" | j "d['id']")
echo "  payout $PO created (2000 sat to $PAYEE)"
for i in $(seq 1 24); do
  ST=$(curl -s "${H[@]}" "$BT/api/v1/stores/$STORE/payouts/$PO")
  STATE=$(echo "$ST" | j "d['state']"); [ "$STATE" = "InProgress" ] || [ "$STATE" = "Completed" ] && break; sleep 5
done
PROOF=$(echo "$ST" | python3 -c "import json,sys;d=json.load(sys.stdin);p=d.get('paymentProof') or {};print(p.get('TransactionId') or p.get('transactionId') or '')")
echo "  payout state: $STATE proof txid: $PROOF"
[ "$STATE" = "InProgress" ] || [ "$STATE" = "Completed" ] || fail "payout not paid: $STATE (signerd/btcpay logs)"
SEQ=$(curl -s -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:7390/v1/status | j "d['seq']"); echo "  enclave seq now $SEQ"; echo "$SEQ" > "$S/seq-after-payout"
[ "$SEQ" -gt "$SEQ0" ] || fail "receipt seq did not advance ($SEQ0 -> $SEQ)"
RTX=$(curl -s -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:7390/v1/receipts | j "d[-1]['txid']")
[ "$RTX" = "$PROOF" ] && pass "the tx BTCPay broadcast is the one the enclave signed (receipt seq $SEQ, txid $RTX)" || fail "receipt txid $RTX != payout proof $PROOF"
docker exec btcpayserver_bitcoind bitcoin-cli -datadir=/data -signet getmempoolentry "$RTX" >/dev/null 2>&1 && pass "node holds $RTX in its mempool" || echo "  (tx not in the local mempool yet/already mined)"

echo "== gate (d.2): a frozen signer refuses, charges nothing, the payout waits"
curl -s -X POST -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:7390/v1/freeze >/dev/null
PAYEE2=$(throwaway_addr)
PO2=$(curl -s "${H[@]}" -X POST "$BT/api/v1/pull-payments/$PP/payouts" -d "{\"destination\":\"$PAYEE2\",\"amount\":\"0.00001\",\"payoutMethodId\":\"BTC-CHAIN\"}" | j "d['id']")
echo "  payout $PO2 created while frozen (1000 sat to $PAYEE2)"
sleep 20
ST2=$(curl -s "${H[@]}" "$BT/api/v1/stores/$STORE/payouts/$PO2" | j "d['state']")
SEQ2=$(curl -s -H "Authorization: Bearer $SIGNER_TOKEN" http://127.0.0.1:7390/v1/status | j "d['seq']")
[ "$ST2" = "AwaitingPayment" ] && [ "$SEQ2" = "$SEQ" ] && pass "frozen: payout $PO2 stays AwaitingPayment, seq unchanged ($SEQ2)" || fail "frozen path: state $ST2 seq $SEQ2"
docker logs --since 2m generated_btcpayserver_1 2>&1 | grep -i "tee-signer" | tail -3 | sed 's/^/  btcpay: /'
docker logs --since 2m generated_btcpayserver_1 2>&1 | grep -q "refused the payout batch: FROZEN" && pass "BTCPay logged the refusal by name (FROZEN)" || fail "no FROZEN refusal in the BTCPay log"

echo "== gate (a) again after a BTCPay restart"
docker restart generated_btcpayserver_1 >/dev/null; sleep 25
HOT2=$(docker exec generated_postgres_1 psql -U postgres -d btcpayserversignet -tAc "select \"DerivationStrategies\" from \"Stores\" where \"Id\"='$STORE'")
echo "$HOT2" | grep -qi '"IsHotWallet": *true' && fail "wallet flagged hot after restart" || pass "still cold after restart"
N2=$(docker exec generated_postgres_1 psql -U postgres -d nbxplorersignet -tAc "select count(*) from nbxv1_metadata where key in ('Mnemonic','MasterHDKey','AccountHDKey')")
[ "$N2" = "0" ] && pass "nbxv1_metadata key rows still 0" || fail "key rows after restart: $N2"
echo "R3 gates: ALL PASS (signer left FROZEN for the operator to unfreeze with the owner key)"
fi
