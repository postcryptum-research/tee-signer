#!/usr/bin/env bash
# scripts/hollow-f01.sh — the hollow red/green of the F-01 fix (REQ-r10-F01 §4 vector 11; RESP-r10-F01 impl, the
# auditor's condition) and of the REQ-r10-O01 refusal (case 8): every protection site the fix adds is removed in turn and `cargo test --test transitions`
# must turn RED, so no vector is hollow and a refactor cannot drop a guard silently. Sources are restored with git
# after each case, so core/src must be clean. Report only; nothing ships.
set -uo pipefail
cd "$(dirname "$0")/.."
if ! git diff --quiet -- core/src; then
  echo "core/src has uncommitted changes — commit or stash first (this script restores with git checkout)"
  exit 2
fi
rc=0
case_() { # <name> <file> <sed-expr> <text that must be present after the edit>
  local name=$1 file=$2 expr=$3 must=$4 out
  echo "== $name"
  sed -i -E "$expr" "$file"
  if ! grep -qF -- "$must" "$file"; then
    echo "   the edit did not apply (expected: $must)"; git checkout -- core/src; rc=3; return
  fi
  git --no-pager diff --stat core/src | tail -1 | sed 's/^/   /'
  out=$(cd core && cargo test -q --test transitions 2>&1 | grep -E '^---- |test result' | head -4)
  echo "$out" | sed 's/^/   /'
  if echo "$out" | grep -q 'FAILED'; then echo "   → RED (the vector bites)"; else echo "   → still GREEN — a hollow vector"; rc=1; fi
  git checkout -- core/src
}
case_ "leg 1: compare's checkpoint rule reverted to height >= (same height, other content = tightening)" \
  core/src/mandate.rs 's/clear\(new\.checkpoint == installed\.checkpoint \|\| new\.checkpoint\.height > installed\.checkpoint\.height\);/clear(new.checkpoint.height >= installed.checkpoint.height);/' 'clear(new.checkpoint.height >= installed.checkpoint.height);'
case_ "leg 2: the bits check dropped" \
  core/src/state.rs 's/if c\.time != r\.time \|\| c\.bits != r\.bits \{/if c.time != r.time {/' 'if c.time != r.time {'
case_ "leg 2: the period-field equality dropped (boundary gate kept)" \
  core/src/state.rs 's/^(\s+)\|\| c\.period_(start_time|bits) != chain\.period_(start_time|bits)$/\1|| false \/\/ HOLLOW/' '|| false // HOLLOW'
case_ "leg 2: the current-period boundary gate dropped (equality checks kept) — the auditor's mutation" \
  core/src/state.rs 's/if r\.height < period_start_height$/if false/' 'if false'
case_ "frozen path: the at-once re-pin disabled (the pre-fix shape: through compare and pending)" \
  core/src/state.rs 's/if s\.chain\.frozen \{/if false \&\& s.chain.frozen {/' 'if false && s.chain.frozen {'
case_ "frozen path: the checkpoint-only check dropped" \
  core/src/state.rs 's/if rest != s\.mandate \{/if false {/' 'if false {'
case_ "REQ-r10-O01: the frozen non-re-pin refusal removed (a loosening parks in pending for ever again)" \
  core/src/state.rs 's/if s\.chain\.frozen \&\& new\.checkpoint == s\.mandate\.checkpoint \{/if false {/' 'if false {'
case_ "leg 3: new_at_init no longer validates" \
  core/src/state.rs 's/^(\s+)mandate\.validate\(\)\?;$/\1let _ = \&mandate; \/\/ HOLLOW/' '// HOLLOW'
if git diff --quiet -- core/src; then echo "== core/src restored: clean"; else echo "== core/src NOT clean"; rc=4; fi
[ $rc -eq 0 ] && echo "== every removed guard turned a vector red (8/8)" || echo "== FAILED: a hollow vector or a bad edit (rc=$rc)"
exit $rc
