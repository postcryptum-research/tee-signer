#!/usr/bin/env bash
# Gate 5: two independent builds must agree on the measurement and every SIGSTRUCT field the
# measurement covers — MRENCLAVE, attributes + mask, misc select + mask, ISV ProdID/SVN — never on
# the signing date, the signer (modulus/MRSIGNER) or the signature (docs/ENCLAVE.md §7, C-R1-3).
set -euo pipefail
A=$1; B=$2
fields() {
  d="$1/sigstruct.dump"
  echo "MRENCLAVE $(grep -A2 'enclave_css.body.enclave_hash.m' "$d" | tail -2 | tr -d ' \n' | sed 's/0x//g')"
  grep -E 'enclave_css.body.(attributes|attribute_mask|misc_select|misc_mask|isv_prod_id|isv_svn)' "$d" | sed -E 's/^\s+//'
}
if diff <(fields "$A") <(fields "$B") >/dev/null; then
  echo "REPRODUCIBLE: $(fields "$A" | head -1); attributes/mask, misc, ProdID/SVN identical"
else
  echo "NOT REPRODUCIBLE:"; diff <(fields "$A") <(fields "$B") | head -20; exit 1
fi
cmp -s "$A/enclave.so" "$B/enclave.so" && echo "enclave.so byte-identical" || echo "enclave.so differs (allowed only if the fields agree; investigate)"
