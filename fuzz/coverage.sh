#!/usr/bin/env bash
# fuzz/coverage.sh <target> — C-R10-7(a) reachability: which functions of signer-core the target's inputs
# (seeds + corpus + regressions) actually reach. Builds the target with coverage instrumentation on the pinned
# nightly, replays the inputs, and prints llvm-cov's report for core/src: the decode/parse/verify/apply/compare
# functions the REQ names first (reached or not, lines executed/total), then per-file line coverage. Full
# reports land in coverage/<target>/ (gitignored). Report only; nothing ships.
#
# findings/ is NOT replayed here: an open reproducer aborts the process before the profile is flushed, which
# would lose the whole run — and the paths it reaches are the corpus's paths anyway.
set -euo pipefail
NIGHTLY=nightly-2026-06-21
cd "$(dirname "$0")"
t=${1:?target}
dirs=("corpus/$t")
[ -d "seeds/$t" ] && dirs+=("seeds/$t")
[ -d "regressions/$t" ] && dirs+=("regressions/$t")
out="coverage/$t"; mkdir -p "$out"
cargo "+$NIGHTLY" fuzz coverage --fuzz-dir . "$t" "${dirs[@]}" >"$out/build.log" 2>&1 \
  || { echo "coverage run failed — see $out/build.log"; exit 1; }
triple=x86_64-unknown-linux-gnu
bin="target/$triple/coverage/$triple/release/$t"
prof="$out/coverage.profdata"
llvm_cov="$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/$triple/bin/llvm-cov"
[ -x "$llvm_cov" ] || { echo "llvm-cov missing: rustup component add llvm-tools-preview --toolchain $NIGHTLY"; exit 2; }
demangle=cat; command -v rustfilt >/dev/null && demangle=rustfilt \
  || echo "note: rustfilt not installed (cargo install rustfilt --locked) — symbol names stay mangled"
# per function: Name Regions Missed Cover Lines Missed Cover [Branches Missed Cover]; the name is one token
# while still mangled, so parse first and demangle after
"$llvm_cov" report "$bin" -instr-profile="$prof" -sources ../core/src -show-functions 2>/dev/null >"$out/functions.raw"
awk 'NF>=7 && $1 !~ /^(Filename|---|TOTAL)/ && $5 ~ /^[0-9]+$/ {
       e=$5-$6; printf "   %-7s %5d/%-5d %s\n", (e>0 ? "reached" : "-"), e, $5, $1 }' "$out/functions.raw" \
  | "$demangle" | sort -k4 >"$out/functions.txt"
# per file: Filename Regions Missed Cover Functions Missed Executed Lines Missed Cover [Branches ...]
"$llvm_cov" report "$bin" -instr-profile="$prof" -sources ../core/src 2>/dev/null >"$out/files.raw"
awk 'NF>=10 && $1 !~ /^(Filename|---)/ {
       printf "   %-22s functions %3d/%-3d  lines %7s  regions %7s\n", $1, $5-$6, $5, $10, $4 }' "$out/files.raw" >"$out/files.txt"
echo "== $t: functions of core/src named by the REQ (decode/parse/verify/apply/compare/validate/finish/mnemonic/hash)"
grep -E 'decode|parse_nv_attest|certified_counter|verify|compare|validate|apply_|finish|mnemonic|to_seed|hash|digest' "$out/functions.txt" \
  | grep -vE '\{closure|::fmt|Debug|Clone|PartialEq' | head -80
echo "== $t: per-file line coverage of core/src (inputs: ${dirs[*]})"
cat "$out/files.txt"
echo "   full reports: $out/functions.txt, $out/files.txt"
# phase 2 pass (iii): the dispatcher target also reaches enclave/rcore (the shell) — report it the same way
if [ "$t" = dispatch ]; then
  "$llvm_cov" report "$bin" -instr-profile="$prof" -sources ../enclave/rcore/src -show-functions 2>/dev/null >"$out/rcore-functions.raw"
  awk 'NF>=7 && $1 !~ /^(Filename|---|TOTAL)/ && $5 ~ /^[0-9]+$/ {
         e=$5-$6; printf "   %-7s %5d/%-5d %s\n", (e>0 ? "reached" : "-"), e, $5, $1 }' "$out/rcore-functions.raw" \
    | "$demangle" | sort -k4 >"$out/rcore-functions.txt"
  "$llvm_cov" report "$bin" -instr-profile="$prof" -sources ../enclave/rcore/src 2>/dev/null >"$out/rcore-files.raw"
  awk 'NF>=10 && $1 !~ /^(Filename|---)/ {
         printf "   %-22s functions %3d/%-3d  lines %7s  regions %7s\n", $1, $5-$6, $5, $10, $4 }' "$out/rcore-files.raw" >"$out/rcore-files.txt"
  echo "== $t: functions of enclave/rcore/src (ops, session, envelope, recovery, sgx nosgx arms)"
  grep -vE '\{closure|::fmt|Debug|Clone|PartialEq' "$out/rcore-functions.txt"
  echo "== $t: per-file line coverage of enclave/rcore/src"
  cat "$out/rcore-files.txt"
  echo "   full reports: $out/rcore-functions.txt, $out/rcore-files.txt"
fi
