#!/usr/bin/env bash
# C-R10-7(b) — the hollow-harness guard: prove the oracles FIRE when a guard in core/ is reverted.
# Each case edits ONE guard in the working tree (sed), runs the stable replay gate (expected RED),
# prints the verdict, and restores core/ with git. Refuses to start unless core/ is clean; checks that
# core/ is clean at the end. Nothing is committed; nothing here ever reaches main.
#   fuzz/injected-defects.sh            run every case
# The auditor re-runs this in a decorrelated clone (RESP-r10 C7). Cases are phase 1 (decoders); phase 2
# adds the Σ-overflow guard (F7) and the C-R9-C freshness gate (F10).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
[ -z "$(git status --porcelain core/ enclave/rcore/src/)" ] || { echo "core/ or enclave/rcore/src/ is not clean; refusing to edit them"; exit 2; }
rc=0
gate() {
  (cd fuzz && cargo test -q --no-default-features --test replay 2>&1 \
    | grep -E 'test result|fails its oracle|C-R10|C-R9|F10|Dec::|not reflexive|STATE_INVALID|POLICY_TOO_EXPENSIVE|R11' | sed 's/^thread.*panicked at //' | sort -u | head -6)
}
case_() { # <name> <file> <sed-expr> <text that must be present after the edit>
  local name=$1 file=$2 expr=$3 must=$4 out
  echo "== $name"
  sed -i -E "$expr" "$file"
  if ! grep -qF -- "$must" "$file"; then echo "   the edit did not apply (expected: $must)"; git checkout -- core/ enclave/rcore/src/; rc=3; return; fi
  git --no-pager diff --stat core/ enclave/rcore/src/ | tail -1 | sed 's/^/   /'
  out=$(gate)
  echo "$out" | sed 's/^/   /'
  if echo "$out" | grep -q 'failed'; then echo "   → CAUGHT by the replay gate"; else echo "   → NOT CAUGHT — a hollow oracle"; rc=1; fi
  git checkout -- core/ enclave/rcore/src/
}

case_ "C-R10-2: Mandate::decode without finish() (trailing bytes accepted)" \
  core/src/mandate.rs 's/^(\s+)d\.finish\(\)\?;$/\1let _ = d.remaining();/' 'let _ = d.remaining();'
case_ "C-R10-2: Message::decode without finish()" \
  core/src/update.rs 's/^(\s+)d\.finish\(\)\?;$/\1let _ = d.remaining();/' 'let _ = d.remaining();'
case_ "C-R10-2: State::decode without finish()" \
  core/src/state.rs 's/^(\s+)d\.finish\(\)\?;$/\1let _ = d.remaining();/' 'let _ = d.remaining();'
case_ "C-R10-2: Receipt::decode without finish()" \
  core/src/receipt.rs 's/^(\s+)d\.finish\(\)\?;$/\1let _ = d.remaining();/' 'let _ = d.remaining();'
case_ "C-R10-1/3: domain tag collapsed (UNFREEZE signs under the CANCEL domain)" \
  core/src/update.rs 's#pub const UNFREEZE: &str = "tee-signer/unfreeze/v1";#pub const UNFREEZE: \&str = "tee-signer/cancel/v1";#' 'pub const UNFREEZE: &str = "tee-signer/cancel/v1";'
case_ "C-R9-A: nonce mismatch reported as TPM_SIG (reason order broken)" \
  core/src/tpm_attest.rs '/if a\.extra != \*nonce \{/{n;s/Reason::TpmNonce/Reason::TpmSig/}' 'return Err(Reason::TpmSig);
    }
    if a.index_name'
case_ "C-R9-A: the safe byte no longer bounds-checked (any value parses)" \
  core/src/tpm_attest.rs 's/if safe > 1 \{/if safe > 255 {/' 'if safe > 255 {'
case_ "Dec::list bound dropped (count above max accepted)" \
  core/src/encoding.rs 's/if n > max_count \{/if n > usize::MAX {/' 'if n > usize::MAX {'
case_ "C-R10-5: compare no longer reflexive (version check inverted)" \
  core/src/mandate.rs 's/clear\(installed\.version == new\.version\);/clear(installed.version != new.version);/' 'clear(installed.version != new.version);'
# F-2026-11-20-01 fixed (RESP-r10-F01 leg 1): the pre-fix compare line brought back must be caught by the four
# F-01 reproducers that moved findings/ -> regressions/ (C-R10-5 both directions)
case_ "C-R10-5 / F-01: compare's checkpoint rule reverted to height >= (same height, other content = tightening)" \
  core/src/mandate.rs 's/clear\(new\.checkpoint == installed\.checkpoint \|\| new\.checkpoint\.height > installed\.checkpoint\.height\);/clear(new.checkpoint.height >= installed.checkpoint.height);/' 'clear(new.checkpoint.height >= installed.checkpoint.height);'

# --- phase 2, pass (i): F6 / F4 oracles (REQ-r10 phase 2 §2; C-R10-6, C-R10P2-2, C-F01-1, REQ-r10-O01) ---
case_ "C-R10-6: add_work_le made wrapping (the carry-out check dropped)" \
  core/src/headers.rs 's/^(\s+)if carry != 0 \{$/\1if false {/' 'if false {'
case_ "R11 C-EXT1-3: validate-on-open removed (an invalid sealed state is read as if sound)" \
  enclave/rcore/src/ops.rs 's/if state\.mandate\.validate\(\)\.is_err\(\) \{/if false {/' 'if false {'
case_ "R11 C-EXT1-4: the derivation cap's refusal removed (the scan never says POLICY_TOO_EXPENSIVE)" \
  core/src/wallet.rs 's/if derivations > cap \{/if false {/' 'if false {'
case_ "F6: the deep-reorg freeze dropped (a fork deeper than max_reorg is judged on work alone)" \
  core/src/headers.rs 's/if depth > max_reorg \{/if false {/' 'if false {'
case_ "F4: the timelock wait dropped (a pending mandate or owner activates at once)" \
  core/src/state.rs 's/if best >= p\.activation_height \{/if true {/' 'if true {'
case_ "REQ-r10-O01: the frozen non-re-pin refusal dropped" \
  core/src/state.rs 's/if s\.chain\.frozen \&\& new\.checkpoint == s\.mandate\.checkpoint \{/if false {/' 'if false {'
# --- phase 2, pass (ii): F7 / F8 oracles (I2, I3, the gap, a cap, C-R10-4 both directions) ---
case_ "I2: the previous-tx txid check dropped (a swapped previous tx is accepted)" \
  core/src/classify.rs 's/if prev\.compute_txid\(\) != txin\.previous_output\.txid \{/if false {/' 'if false {'
case_ "I3: the own-output script check dropped (our hint, someone else's script)" \
  core/src/classify.rs 's/if verify_own_output_script \&\& script\.as_script\(\) != spk\.as_script\(\) \{/if false {/' 'if false {'
case_ "I3: the own-index gap check dropped" \
  core/src/classify.rs 's/if p\.index >= limit \{/if false {/' 'if false {'
case_ "F8: the per-transaction outflow cap dropped" \
  core/src/judge.rs 's/if net_outflow > l\.max_per_tx \{/if false {/' 'if false {'
case_ "C-R10-4 broadened: disarm fires when last_seen_seq EQUALS seq" \
  core/src/judge.rs 's/if \*last_seen_seq > s\.seq \{/if *last_seen_seq >= s.seq {/' 'if *last_seen_seq >= s.seq {'
case_ "C-R10-4 narrowed: the rollback-suspected refusal no longer disarms" \
  core/src/judge.rs 's/Err\(\(Refusal::one\(Reason::FreshnessSeqBehind\), true\)\)/Err((Refusal::one(Reason::FreshnessSeqBehind), false))/' 'FreshnessSeqBehind), false))'
case_ "C-F01-1: the frozen at-once re-pin disabled (through compare and pending again)" \
  core/src/state.rs 's/^(\s+)if s\.chain\.frozen \{$/\1if false \&\& s.chain.frozen {/' 'if false && s.chain.frozen {'

# --- phase 2, pass (iii): F10 — the shell's gates (rcore ops.rs / session.rs, edited and restored like core/) and
# the TPM counter equality (C-R9-C) ---
case_ "F10: SIGN's two-phase check dropped (any PSBT is signed on a charged blob)" \
  enclave/rcore/src/ops.rs 's/if lj\.psbt_hash != signer_core::sha256\(&req\.data\) \|\| lj\.seq != s\.seq \{/if false {/' 'if false {'
case_ "C-R7-3: the session high-water mark no longer refuses an older blob" \
  enclave/rcore/src/session.rs 's/seq >= HWM\.load\(Ordering::Acquire\)/seq.saturating_add(1) > 0/' 'seq.saturating_add(1) > 0'
case_ "C-R7-4: JUDGE no longer checks the boot-arm" \
  enclave/rcore/src/ops.rs '0,/if !session::armed\(\) \{/s//if !session::armed() \&\& false {/' 'if !session::armed() && false {'
case_ "C-R7-4: SIGN no longer checks the boot-arm" \
  enclave/rcore/src/ops.rs '/^fn sign_op/,$ s/if !session::armed\(\) \{/if !session::armed() \&\& false {/' 'if !session::armed() && false {'
case_ "C-R9-C: a Fresh op without a deposited proof proceeds (TPM_REQUIRED dropped)" \
  enclave/rcore/src/ops.rs '0,/return Err\(refuse\(Reason::TpmRequired\.into\(\)\)\);/s//return Ok((env, state));/' 'return Ok((env, state));'
case_ "C-R9-C: the counter equality dropped (any certified value is fresh)" \
  core/src/tpm_attest.rs 's/if counter != anchor\.expected \{/if false {/' 'if false {'
case_ "REQ-r9a: the Anchor pins a value other than the live certified counter" \
  enclave/rcore/src/ops.rs 's/s\.apply_anchor\(&msg, &session::challenge\(\), live\)/s.apply_anchor(\&msg, \&session::challenge(), live.saturating_add(1))/' 'live.saturating_add(1))'
case_ "C-R7-3: the mark no longer ratchets on an accepted owner message" \
  enclave/rcore/src/ops.rs 's/^(\s+)session::raise\(ns\.seq\);$/\1let _ = ns.seq;/' 'let _ = ns.seq;'
case_ "F10: INSTALL skips the wallet check (a mandate for another wallet installs)" \
  enclave/rcore/src/ops.rs 's/if mandate\.wallet != want \{/if false {/' 'if false {'

echo "== core/ and enclave/rcore/src/ restored: $([ -z "$(git status --porcelain core/ enclave/rcore/src/)" ] && echo clean || echo 'DIRTY — check git status')"
[ "$rc" = 0 ] && echo "== every injected defect was caught" || echo "== rc=$rc (1 = a defect was NOT caught; 3 = an edit did not apply)"
exit "$rc"
