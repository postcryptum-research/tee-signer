# Carried conditions — the worked queue

Every actionable condition from a RESP lives here with a target round and a status, per the
trust-bridge rule that a finding left only in a round's prose rots. Prose keeps the reasoning;
this table is what each IMPL REQ must discharge. **Status:** OPEN · IN IMPL (branch) · DISCHARGED
(RESP ref) · LABELED (residual, no code).

| Id | From | Condition | Target | Status |
|---|---|---|---|---|
| C-R3a | RESP-design R3 | header verifier held to the consensus-code bar: target/retarget math, most-cumulative-work, per-network rules incl. testnet-20-min | R4 (`signer-core::headers`) | OPEN |
| C-R3b | R3 | the signet/testnet weak-PoW label is emitted at `GET /v1/status`, not only in docs | R2 (`signerd`) | OPEN |
| C-R3c | R3 | checkpoint only moves forward to an enclave-verified header | R4 | OPEN |
| C-R4a | R4 | own-output search bounded by `ownIndexGap` ≤ 100 and by `maxInputs`/`maxOutputs` | R1 | OPEN |
| C-R4b | R4 | `own_index_bound` monotonic, only within the sealed account path | R1 | OPEN |
| C-R4c | R4 | OP_RETURN explicit: non-zero value, or `opReturn=none` ⇒ refuse | R1 | OPEN |
| C-R5a | R5 ⭐ | state in `POLICY.md` that fee ∈ net outflow and every class counts toward `window.maxOutflow`, so the per-window fee-burn bound is `window.maxOutflow`, not `maxFeeAbs`; name the fee-burn / budget-exhaustion residual | docs | DISCHARGED in `POLICY.md §3` (this commit) |
| C-R5b | R5 | vector: many trusted outputs at max fee ⇒ `CAP_WINDOW` | R1 vectors | OPEN |
| C-R6 | R6 ⭐ | the tightening classifier FAILS TOWARD LOOSENING: field by field on the canonical decoded mandate; any field not provably tightening (unknown, absent, ambiguous) makes the whole update loosening | R1 (`signer-core::policy::compare`) | OPEN — rule written in `POLICY.md §5` (this commit) |
| C-R7 | R7 | on reload the host-supplied sealed blob is untrusted input: seal/MAC verified before use; an older valid blob is the witness's job | R2 (`enclave`) | OPEN |
| C-R8a | R8 | recovery-blob ephemeral key from in-enclave RDRAND, zeroized after use | R2 | OPEN |
| C-R8b | R8 | GCM-nonce uniqueness is structural (fresh ephemeral ⇒ fresh HKDF output ⇒ fresh key; nonce fixed) — stated in `DESIGN.md §2` | docs | DISCHARGED (this commit) |
| C-R8c | R8 | I12 mutation vector: no ecall but init yields the seed or any function of it beyond signatures and public keys | R2 vectors | OPEN |
| C-R9 | R9 | the test-only software owner key is compile-gated and provably absent from any T1/T2 release build; the build asserts it (symbol/feature check) | R2 build | OPEN |
| C-R10a | R10 ⭐ | the build asserts `objdump -d enclave.so \| grep -c cpuid` == 0 | R2 build | OPEN |
| C-R10b | R10 | every enclave crate exact-version pinned, with a provenance line and a REQ to change | R1 (`core/PROVENANCE.md`) | OPEN |
| C-R10c | R10 | secp256k1 context randomization wired to `sgx_read_rand` — a T2 gate, not optional | R2 | OPEN |
| C-R10d | R10 ⭐ | reproducible enclave build: required for T2, recommended for T1 | R2 build / R5 | OPEN |
| C-R10e | R10 | sealing and concurrent-ecall atomicity (commit-seal ordering under concurrency) named as IMPL-PASS gates of R2 | R2 REQ | OPEN |
| C-R11a | R11 | seed generated in-enclave; xpub imported cold; never NBXplorer `GenerateWallet` | R3 (plugin + deploy) | OPEN |
| C-R11b | R11 | cold from the start; the plugin refuses to operate a store whose wallet is `IsHotWallet=true` | R3 | OPEN |
| C-R11c | R11 | e2e vector: `IsHotWallet=false` end to end and zero key material in `nbxv1_metadata` | R3 vectors | OPEN |
| C-R12a | R12 | positive/accept vectors: unlisted within cap accepts; sweep to trusted accepts; valid loosening activates after timelock; valid tightening applies at once | R1 vectors | OPEN |
| C-R12b | R12 | per-invariant mutation vectors: drop `non_witness_utxo` requirement ⇒ lying-`witness_utxo` fee vector passes (I2); host `bip32_derivation` as decision ⇒ change-to-foreign passes (I3); commit-after-sign ⇒ rollback double-spends (I5/I11) | R1/R2 vectors | OPEN |
| C-R12c | R12 | freshness `maxTipLag` boundary vector | R4 vectors | OPEN |
| C-R12d | R12 | = C-R5b | R1 vectors | OPEN |
| C-R12e | R12 | u64 overflow vectors: Σ inputs near `u64::MAX` ⇒ `OVERFLOW`, never wrap | R1 vectors | OPEN |
| C-R13a | R13 | `Rearm { seq }` owner-signed with a nonce; a replayed Rearm cannot re-enable a rolled-back state | R4 | OPEN |
| C-R13b | R13 | the chosen `maxTipLag` exposure stated per network at `GET /v1/status` and in `POLICY.md` | R4 / docs | OPEN — residual text in `POLICY.md §3` (this commit) |
| C-R14 | R14 | `policy diff` mandatory before `policy sign`; the signed digest is derived from the shown canonical bytes | R2 (`owner-cli`) | OPEN |
| C-D3 | owner D3 | owner key: any `hw-signer` backend; encrypted off-box keyfile allowed as the floor; plaintext refused | R2 (`owner-cli`) | OPEN — design text updated (this commit) |
| C-D5 | owner D5 | header feed from the shared signet node, read-only RPC subset | R2 (`signerd`) / deploy | OPEN — `deploy/README.md` updated (this commit) |
