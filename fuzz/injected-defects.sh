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
[ -z "$(git status --porcelain core/)" ] || { echo "core/ is not clean; refusing to edit it"; exit 2; }
rc=0
gate() {
  (cd fuzz && cargo test -q --no-default-features --test replay 2>&1 \
    | grep -E 'test result|fails its oracle|C-R10|C-R9|Dec::|not reflexive' | sed 's/^thread.*panicked at //' | sort -u | head -6)
}
case_() { # <name> <file> <sed-expr> <text that must be present after the edit>
  local name=$1 file=$2 expr=$3 must=$4 out
  echo "== $name"
  sed -i -E "$expr" "$file"
  if ! grep -qF -- "$must" "$file"; then echo "   the edit did not apply (expected: $must)"; git checkout -- core/; rc=3; return; fi
  git --no-pager diff --stat core/ | tail -1 | sed 's/^/   /'
  out=$(gate)
  echo "$out" | sed 's/^/   /'
  if echo "$out" | grep -q 'failed'; then echo "   → CAUGHT by the replay gate"; else echo "   → NOT CAUGHT — a hollow oracle"; rc=1; fi
  git checkout -- core/
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

echo "== core/ restored: $([ -z "$(git status --porcelain core/)" ] && echo clean || echo 'DIRTY — check git status')"
[ "$rc" = 0 ] && echo "== every injected defect was caught" || echo "== rc=$rc (1 = a defect was NOT caught; 3 = an edit did not apply)"
exit "$rc"
