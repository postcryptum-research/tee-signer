# Header vectors

`signet-322560-324700.hex`: 2141 consecutive signet block headers (80 bytes each, hex, one per
line), heights 322560 (a retarget boundary, 160 × 2016) through 324700, fetched 2026-11-03 over
read-only RPC (`getblockheader <hash> false`) from the shared signet node on the dev host (owner
decision D5). Covers the retarget at height 324576 (161 × 2016), so the verifier's retarget math is
checked against the real chain. Signet's proof-of-work is cheap; these are a correctness vector,
not a security claim.
