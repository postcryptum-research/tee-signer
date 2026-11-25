#!/usr/bin/env bash
# fuzz/run.sh <target> [seconds=3600] [jobs=4] — a discovery run with the pinned nightly (REQ-r10 §3/§4).
# Limits per target: -max_len from the proto bounds the type lives under, -malloc_limit_mb BELOW the bound
# (an allocating untrusted length is a V2 DoS finding, RESP-r10), -timeout, -rss_limit. The corpus dir is the
# first argument to libFuzzer (new inputs land there); regressions are read, never written. Logs: fuzz-*.log.
# Laptop only — never the shared box or the node (REQ-r10 §4). Nothing built here ships.
set -euo pipefail
NIGHTLY=nightly-2026-06-21
cd "$(dirname "$0")"
t=${1:?target name (see Cargo.toml [[bin]] or `ls fuzz_targets`)}; secs=${2:-3600}; jobs=${3:-4}
case "$t" in
  proto_decode|state_decode)              maxlen=65536; malloc=64 ;;
  mandate_decode|mandate_compare|message_decode|receipt_decode|encoding_dec|cross_type) maxlen=8192; malloc=16 ;;
  tpm_attest)                             maxlen=1024;  malloc=16 ;;
  bip39)                                  maxlen=512;   malloc=16 ;;
  headers)                                maxlen=8192;  malloc=64 ;;   # a mode byte + up to 64 raw headers, or a script
  state_ops)                              maxlen=256;   malloc=16 ;;   # 24 eight-byte step records + slack
  work_add)                               maxlen=64;    malloc=16 ;;
  classify)                               maxlen=65536; malloc=64 ;;   # raw PSBTs (the proto bound is 256 KiB; 64 KiB keeps the fuzzer fast) or a 48-byte script
  judge)                                  maxlen=256;   malloc=16 ;;   # 7 knob bytes + a PSBT script
  *) echo "unknown target $t"; exit 2 ;;
esac
dirs=("corpus/$t"); flags=()                      # first dir = where libFuzzer writes new inputs
[ -d "seeds/$t" ] && dirs+=("seeds/$t")            # hand-written seeds (tests/replay.rs write_seeds), read-only here
[ -d "regressions/$t" ] && dirs+=("regressions/$t")
[ -f "dict/$t.dict" ] && flags+=("-dict=dict/$t.dict")
mkdir -p "corpus/$t"
# jobs>1: libFuzzer fork mode — one parent, N workers, everything on stdout (so several targets can run side
# by side, each redirected to its own log); the parent exits non-zero on the first crash unless
# FUZZ_IGNORE_CRASHES=1, which keeps exploring past a known OPEN finding while still writing every crash.
# jobs=1: a single foreground process; the exit code is the crash status (CI smoke).
if [ "$jobs" -gt 1 ] || [ "${FUZZ_IGNORE_CRASHES:-0}" = 1 ]; then flags+=("-fork=$jobs"); fi   # -ignore_crashes needs fork mode
[ "${FUZZ_IGNORE_CRASHES:-0}" = 1 ] && flags+=("-ignore_crashes=1")
exec cargo "+$NIGHTLY" fuzz run --fuzz-dir . "$t" "${dirs[@]}" -- \
  -max_len="$maxlen" -timeout=10 -rss_limit_mb=1024 -malloc_limit_mb="$malloc" \
  -max_total_time="$secs" -print_final_stats=1 "${flags[@]}"
