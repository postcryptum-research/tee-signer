#!/usr/bin/env bash
# Gate 5: two independent builds must agree on MRENCLAVE and every SIGSTRUCT field except the
# signing date and the signature material (docs/ENCLAVE.md §7, C-R1-3 / C-R2-3).
set -euo pipefail
A=$1; B=$2
strip() { grep -vE 'header.date|modulus|signature|q1|q2|exponent' "$1/sigstruct.dump" | sed -E 's/^\s+//' ; }
if diff <(strip "$A") <(strip "$B") >/dev/null; then
  echo "REPRODUCIBLE: SIGSTRUCT (minus date/signature) identical: MRENCLAVE $(grep -A2 'enclave_hash.m' "$A/sigstruct.dump" | tail -2 | tr -d ' \n' | sed 's/0x//g')"
else
  echo "NOT REPRODUCIBLE:"; diff <(strip "$A") <(strip "$B") | head -20; exit 1
fi
cmp -s "$A/enclave.so" "$B/enclave.so" && echo "enclave.so byte-identical" || echo "enclave.so differs (allowed only if SIGSTRUCT agrees; investigate)"
