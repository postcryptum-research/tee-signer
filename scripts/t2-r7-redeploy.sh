#!/usr/bin/env bash
# C-R7-13 — redeploy the live T2 sidecar on the ceremony-signed R7 pause build, re-initialise the
# wallet with the YubiKey owner, install the mandate, run the restart drill (owner's arm), re-point
# the T2 BTCPay store and plugin. Run ON THE LAPTOP by the owner, YubiKey plugged in:
#   scripts/t2-r7-redeploy.sh
# Two PIN + touch moments (mandate install, arm) and one recovery-passphrase prompt. Files move only
# by scp (laptop -> build box relay -> node and back); every server answer is a file in the node's
# exchange directory (= /exchange in the sidecar); the laptop never talks to the signer.
set -euo pipefail
cd "$(dirname "$0")/.."
BOX=andrey@94.130.18.162
NODE=azureuser@52.236.130.102
RELAY='~/tee-signer-exchange-relay'      # on the box
NX='~/tee-signer-exchange'               # on the node
D=.local/signet-t2                       # the owner's directory on the laptop
X=$D/exchange
OC=owner/owner-cli/target/debug/owner-cli
MRE=ca5c1a6adfb439be65afba2acae246507c6d87f0c0d399345015ff0590e27c80
STAMP=$(date -u +%Y%m%d-%H%M%S)
LOG=$D/r7-deploy-$STAMP.log
exec > >(tee -a "$LOG") 2>&1
say() { printf '\n== %s\n' "$*"; }
on_node() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$BOX" "ssh -o BatchMode=yes -o ConnectTimeout=20 $NODE '$*'"; }
to_node() {  # laptop files -> box relay -> node exchange dir
  scp -q "$@" "$BOX:$RELAY/"
  local n=(); for f in "$@"; do n+=("$RELAY/$(basename "$f")"); done
  ssh -o BatchMode=yes "$BOX" "scp -q ${n[*]} $NODE:$NX/"
}
from_node() {  # names in the node exchange dir -> box relay -> laptop $X
  local a=() b=(); for f in "$@"; do a+=("$NODE:$NX/$f"); b+=("$BOX:$RELAY/$f"); done
  ssh -o BatchMode=yes "$BOX" "scp -q ${a[*]} $RELAY/"
  scp -q "${b[@]}" "$X/"
}
run_step() {  # run $X/$1 on the node, fetch its log, stop on failure
  to_node "$X/$1"
  local rc=0; on_node "bash $NX/$1 > $NX/$1.log 2>&1" || rc=$?
  from_node "$1.log"; sed 's/^/  | /' "$X/$1.log"
  [ "$rc" = 0 ] || { echo "!! $1 failed (exit $rc) — stopping; nothing after this step ran"; exit "$rc"; }
}
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d=d.get("response",d) if isinstance(d,dict) else d
for k in sys.argv[2:]: print(k+"="+str(d.get(k)))' "$@"; }

say "0. preflight (laptop)"
[ -x "$OC" ] || { echo "build owner-cli first: cd owner/owner-cli && cargo build"; exit 1; }
for f in owner.pub recovery.pub nonce.txt; do [ -s "$X/$f" ] || { echo "missing $X/$f"; exit 1; }; done
[ -s "$D/recovery-r7.key" ] || { echo "missing $D/recovery-r7.key"; exit 1; }
"$OC" pubkey --key piv:9a | grep -q "^$(cat "$X/owner.pub")$" || { echo "YubiKey 39252737 slot 9a not present or not the owner key — plug it in"; exit 1; }
ssh -o BatchMode=yes -o ConnectTimeout=20 "$BOX" "mkdir -p -m 700 $RELAY" && echo "box relay ok"
echo "log: $LOG"

say "1. server: stop the R6 sidecar, set the retired wallet's state aside, start the R7 build, init, quote, status"
cat > "$X/step1.sh" <<'REMOTE'
set -euo pipefail
X=$HOME/tee-signer-exchange; C=tee-btcpay-tee-signer-1; R=retired-51dee44d-2026-11-10
chmod 1777 "$X"   # the sidecar writes here as uid 999
echo "before: $(docker ps -a --format '{{.Status}} / image {{.Image}}' -f name=$C)"
OLD=$(docker exec $C cat /var/lib/signerd/token 2>/dev/null || echo none)
docker stop $C >/dev/null && echo "stopped $C"
docker run --rm -v tee-btcpay_tee_signer_datadir:/v ubuntu:22.04 sh -c "mkdir -p /v/$R; for f in state.sealed receipts.jsonl token; do [ -e /v/\$f ] && mv -v /v/\$f /v/$R/; done; echo 'state volume now:'; ls -la /v; ls -la /v/$R"
cd "$HOME/tee-signer-btcpay"
TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs "$HOME/tee-signer/btcpay/docker/stack.sh" up --no-deps tee-signer
for i in $(seq 1 30); do docker exec $C signerd status --state-dir /var/lib/signerd --out /exchange/status0.json >/dev/null 2>&1 && break; sleep 3; done
echo "after:  $(docker ps --format '{{.Status}} / image {{.Image}}' -f name=$C), image id $(docker inspect -f '{{.Image}}' $C | cut -c8-19)"
docker logs --tail 4 $C 2>&1 | sed 's/^/  log: /'
NEW=$(docker exec $C cat /var/lib/signerd/token)
printf %s "$NEW" > "$HOME/tee-signer/token"; chmod 600 "$HOME/tee-signer/token"
( umask 077; printf %s "$NEW" > "$X/token.new" )
echo "token rotated: $([ "$OLD" != "$NEW" ] && echo yes || echo NO); old token -> HTTP $(curl -s -o /dev/null -w %{http_code} -H "Authorization: Bearer $OLD" http://127.0.0.1:7390/v1/status); new token -> HTTP $(curl -s -o /dev/null -w %{http_code} -H "Authorization: Bearer $NEW" http://127.0.0.1:7390/v1/status)"
python3 -c 'import json; d=json.load(open("'"$X"'/status0.json"))["response"]; print("status before init:", {k:d.get(k) for k in ("enclave","initialised","tier","mrenclave","boot_armed","auto_arm")})'
docker exec $C signerd init  --state-dir /var/lib/signerd --network signet --owner-pk-file /exchange/owner.pub --recovery-pk-file /exchange/recovery.pub --out /exchange/init-response.json
docker exec $C signerd quote --state-dir /var/lib/signerd --nonce-file /exchange/nonce.txt --out /exchange/quote.json
docker exec $C signerd status --state-dir /var/lib/signerd --out /exchange/status.json
echo "step1 done"
REMOTE
run_step step1.sh
from_node init-response.json quote.json status.json token.new
install -m 600 "$X/token.new" "$D/token.new"; rm -f "$X/token.new"
field "$X/status.json" enclave initialised installed tier mrenclave boot_armed auto_arm nonce seq best_height

say "2. laptop: verify the quote and the identity card, write the wallet record (nothing is sent)"
NEWREC=$D/wallet-${MRE:0:8}.json
"$OC" init --response "$X/init-response.json" --network signet --owner piv:9a --recovery-pk-file "$X/recovery.pub" \
  --out "$NEWREC" --expect-mrenclave "$MRE" --quote "$X/quote.json" --nonce-file "$X/nonce.txt" \
  --accept-advisory INTEL-SA-00615:2026-11-10:reviewed-MMIO-stale-data-SDK-2.28-no-MMIO-in-the-enclave
FP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$NEWREC")
XPUB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["xpub"])' "$NEWREC")
echo "new wallet: fingerprint $FP, xpub ${XPUB:0:20}…"
echo "-- recovery-verify: type the passphrase of $D/recovery-r7.key"
"$OC" recovery-verify --wallet "$NEWREC" --recovery-key "$D/recovery-r7.key"
if [ -f "$D/wallet.json" ] && grep -q '"mrenclave": "51dee44d' "$D/wallet.json"; then mv "$D/wallet.json" "$D/wallet-51dee44d-retired-2026-11-10.json"; echo "old record archived: $D/wallet-51dee44d-retired-2026-11-10.json"; fi
cp "$NEWREC" "$D/wallet.json"; mv -f "$D/token.new" "$D/token"; echo "record: $D/wallet.json; token: $D/token"

say "3. mandate: the T2 mandate re-targeted to the new wallet, checkpoint from the public signet explorer"
python3 - "$D/mandate.json" "$D/mandate-r7.json" "$FP" <<'PY'
import json,sys
m=json.load(open(sys.argv[1])); m["wallet"]["fingerprint"]=sys.argv[3]
json.dump(m,open(sys.argv[2],"w"),indent=1); print("mandate-r7.json: fingerprint", sys.argv[3], "caps unlisted", m["destinations"]["unlisted"], "window", m["limits"]["window"])
PY
"$OC" policy-build --json "$D/mandate-r7.json" --esplora https://mempool.space/signet/api --write | tail -3
echo "-- policy-sign (INSTALL, nonce 0): PIN + touch on the YubiKey"
"$OC" --status-file "$X/status.json" --wallet-record "$D/wallet.json" --out "$X/policy-install.msg" policy-sign --json "$D/mandate-r7.json" --key piv:9a
cat > "$X/step2.sh" <<'REMOTE'
set -uo pipefail; C=tee-btcpay-tee-signer-1
rm -f "$HOME/tee-signer-exchange/token.new"
docker exec $C signerd submit --state-dir /var/lib/signerd --file /exchange/policy-install.msg --out /exchange/policy-install.result.json; echo "submit exit=$?"
docker exec $C signerd status --state-dir /var/lib/signerd --out /exchange/status.json
REMOTE
to_node "$X/policy-install.msg"; run_step step2.sh
from_node policy-install.result.json status.json
echo "install result: $(cat "$X/policy-install.result.json" | cut -c1-200)"
field "$X/status.json" installed nonce mandate_hash boot_armed

say "4. restart drill: the sidecar restarts, the enclave waits for the owner (boot_armed false)"
cat > "$X/step3.sh" <<'REMOTE'
set -euo pipefail; C=tee-btcpay-tee-signer-1
docker restart $C >/dev/null && echo "restarted $C"
for i in $(seq 1 30); do docker exec $C signerd status --state-dir /var/lib/signerd --out /exchange/status-after-restart.json >/dev/null 2>&1 && break; sleep 3; done
echo "restart done"
REMOTE
run_step step3.sh
from_node status-after-restart.json
field "$X/status-after-restart.json" initialised installed boot_armed boot_challenge nonce seq
echo "-- arm: PIN + touch on the YubiKey (owner-cli refuses if the enclave remembers fewer operations than this record)"
"$OC" --status-file "$X/status-after-restart.json" --wallet-record "$D/wallet.json" --out "$X/arm.msg" arm --key piv:9a
cat > "$X/step4.sh" <<'REMOTE'
set -uo pipefail; C=tee-btcpay-tee-signer-1
docker exec $C signerd submit --state-dir /var/lib/signerd --file /exchange/arm.msg --out /exchange/arm.result.json; echo "submit exit=$?"
docker exec $C signerd status --state-dir /var/lib/signerd --out /exchange/status-armed.json
REMOTE
to_node "$X/arm.msg"; run_step step4.sh
from_node arm.result.json status-armed.json
echo "arm result: $(cat "$X/arm.result.json" | cut -c1-200)"
field "$X/status-armed.json" boot_armed nonce seq

say "5. T2 BTCPay: the store's cold wallet = the new xpub, the plugin = the new token"
sed "s|@FP@|$FP|; s|@XPUB@|$XPUB|" > "$X/step5.sh" <<'REMOTE'
set -uo pipefail
BT=http://127.0.0.1:7392; KEY=$(cat "$HOME/tee-signer-btcpay/e2e/apikey"); STORE=$(cat "$HOME/tee-signer-btcpay/e2e/store"); TOK=$(cat "$HOME/tee-signer/token")
echo "store wallet: HTTP $(curl -s -o /dev/null -w %{http_code} -H "Authorization: token $KEY" -H 'content-type: application/json' -X PUT "$BT/api/v1/stores/$STORE/payment-methods/BTC-CHAIN" -d "{\"enabled\":true,\"config\":\"[@FP@/84'/1'/0']@XPUB@\"}")"
echo "plugin settings: HTTP $(curl -s -o /dev/null -w %{http_code} -H "Authorization: token $KEY" -H 'content-type: application/json' -X PUT "$BT/plugins/teesigner/api/$STORE/settings" -d "{\"signerdUrl\":\"http://tee-signer:7390\",\"token\":\"$TOK\",\"minConfirmations\":0,\"fallbackFeeRateSatVb\":5}")"
curl -s -H "Authorization: token $KEY" "$BT/plugins/teesigner/api/$STORE/status" | python3 -c 'import sys,json; d=json.load(sys.stdin); e=d.get("enclave") or {}; print("plugin status:", {k:d.get(k) for k in ("configured","walletIsHot","xpubMatches","processorEnabled","error")}, "enclave:", {k:e.get(k) for k in ("tier","installed","bootArmed","seq")})'
REMOTE
run_step step5.sh

say "done — evidence: $LOG, records $D/wallet.json (new) and $D/wallet-51dee44d-retired-2026-11-10.json (old), files in $X/"
