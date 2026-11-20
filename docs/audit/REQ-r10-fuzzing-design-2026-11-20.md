# REQ-r10 — coverage-guided fuzzing of the critical sections (design REQ)

**Date:** 2026-11-20. **Status:** **DESIGN-PASS (CONDITIONAL)** 2026-11-20 → `RESP-r10-fuzzing-design-2026-11-20.md` (the auditor, same day; C1–C7 carried as `C-R10-1…7` + forward `C-R10-F` in `CONDITIONS.md`; §6 answered: C-R9-C table + direct invariants for F10, no state-machine model; `#[path]` fixtures; fuzz-replay joins the IMPL-PASS bar). Phase 1 waits for the owner's go. **Owner's ask (2026-11-20):** «кроме покрытия тестами ещё fuzzing для
критических секций кода» — fuzzing added next to the golden vectors, the hollow-test mutations and the unit tests.
**Scope of this REQ:** which code is fuzzed, with which oracles, where the harness lives, how a finding is handled.
**Not in scope:** any change to `core/` or `enclave/` — the harness uses the public API of `signer-core` and the
`nosgx` build of `rcore` as they are. A seam the harness turns out to need is a supplement REQ, not a commit.

## 1. Why fuzzing, and what it adds to what exists

Today the trusted core is held by three kinds of tests: **golden vectors** (`vectors/r1`, 54 files, replayed
through the real ecalls by `signerd`'s replay command), **hollow-test mutations** (`core/tests/transitions.rs`, each
guard removed ⇒ its vector goes green; C-R12b) and **unit/integration tests** per module (`core/tests/`,
`enclave/rcore` under `nosgx,test-init`). All of them are *chosen* inputs: they prove the checks the designers
thought of. Fuzzing explores the inputs nobody chose — malformed, truncated, oversized, boundary-valued, or
canonical-looking but not canonical bytes — against invariants that must hold for *every* input.

What a passing fuzz run is evidence for (and only this):

1. **No panic, no abort, no unbounded allocation, no timeout on any untrusted byte string** at every entry
   point that takes bytes from the host. `signer-core` is `#![forbid(unsafe_code)]` and both profiles are
   `panic = "abort"`, so a panic inside the enclave kills the enclave: the signer is down until a reload, and
   after R7 a reload waits for the owner's `Arm` (or the TPM proof). V2 of the threat model (an unprivileged
   host user who can talk to `signerd`) gets an availability lever for the price of one request. A panic is
   also, nearly always, a reasoning gap in a parser.
2. **Canonicality** of every wire type that is hashed or signed: `decode(b) = Ok(x)` ⇒ `encode(x) = b`, and
   `decode(encode(x)) = x`. Two byte strings for one mandate or one message would be a hash/signature confusion.
3. **Fail-closed under mutation**: any mutation of a signed object (owner message, `TPMS_ATTEST` + signature,
   witness token) is refused, with the reason order the auditor fixed (C-R9-A: structure → nonce → index →
   signature).
4. **Policy invariants on accept** (POLICY.md §3, §5): an `Accept` never exceeds a per-tx cap, a window cap, the
   fee caps, the gap bound, the freshness bound; the charged state is monotone and charges exactly what was
   accepted; an expired, frozen or unarmed state never accepts.

What it is **not** evidence for: that the verdicts match POLICY.md's meaning beyond the encoded invariants (that
remains the vectors' and the auditor's job); SGX-specific behaviour (`nosgx` stand-ins for sealing and randomness);
side channels; the C# plugin.

## 2. The critical sections — target list

"Critical" = takes bytes from an untrusted party and its result decides, or feeds into, a signature or a seal.
Priority P0 is the `no_std` core (pure, host-runnable byte for byte); P1 the enclave shell under `nosgx`; P2 the
parsers on the **owner's** laptop that read what the node sends (a different trust domain, same shape of risk).

| # | Target (entry point) | Input the fuzzer owns | Oracle (beyond "no panic / no OOM / no timeout") | Seeds | Prio |
|---|---|---|---|---|---|
| F1 | `proto::{InitRequest, TestInitRequest, InitResponse, SealedResponse, StatusResponse, PolicyResponse, IdentityCard, TpmProof, Response}::decode` | raw bytes, `-max_len` = the type's proto bound (`MAX_SMALL`, `MAX_MESSAGE`, `MAX_SEALED`) | round trip both ways (§1.2); `Dec::finish` rejects trailing bytes | encodings produced by the replay tests | P0 |
| F2 | `Mandate::decode` → `validate` → `encode`; `Mandate::hash`; `mandate::compare(a, b)` | raw bytes; for `compare`, two decoded mandates (the second a structured mutation of the first via `arbitrary`) | round trip; `validate` is total (never panics on a decoded value); `compare` never reports `Tighten` in both directions for two different mandates; every `Immutable` field change is flagged | the 54 vectors' `mandate_hex` | P0 |
| F3 | `update::Message::decode` → `verify(pk)`; `Message::encode` | raw bytes | round trip; `verify` false for every mutation of a seeded honest message (P-256 — the fuzzer cannot forge, so `true` only on a byte-identical seed) | honest messages signed with the test P-256 keys from `core/tests/common` | P0 |
| F4 | `State::decode`/`encode`; `State::apply_message`, `apply_arm`, `apply_anchor` | raw state bytes; (state from the fixture, arbitrary message bytes) | round trip; `apply_*` returns `Err` for every message not honestly signed; on honest structured messages: nonce strictly increases, at most one pending owner, a loosening never applies before its timelock, a freeze taken unarmed persists (C-R7-6) | the vectors' `state_hex` | P0 |
| F5 | `tpm_attest::parse_nv_attest`, `certified_counter`, `verify_nv_certify`; `build_nv_attest` → parse | raw attest bytes (`MAX_ATTEST_LEN`), plus structured mutations of a built honest attest | each mutation lands on **its own** reason in the fixed order (C-R9-A); build→parse is the identity; no counter is ever returned without the signature verifying | the honest attest the `core/tests/tpm_attest.rs` tests build; the real Intel PTT `TPMS_ATTEST` from the `e2e-tss-local` run if it is on the laptop | P0 |
| F6 | `headers::apply_headers(state, raw)` | arbitrary `[[u8; 80]]` batches; structured: chains mined from the fixture checkpoint with `arbitrary`-chosen bits/time/prev mutations and fork depths | `best` never moves to less cumulative work; a reorg deeper than `max_reorg` ⇒ `frozen` **and** `CHAIN_REORG`; frozen stays frozen; the return value equals the main-chain growth; per-network rules as in C-R3a | `vectors/headers/signet-322560-324700.hex` and the regtest miner in `host/signerd/src/replay.rs` | P0 |
| F7 | `classify(secp, psbt_bytes, account, mandate, bound)` | raw PSBT bytes (`MAX_PSBT`); structured: `core/tests/common::build_psbt` driven by `arbitrary` (own/foreign inputs, own/trusted/unlisted/foreign/op_return outputs, amounts, hints, versions, sighash) | `Ok` ⇒ every `Own` input has a `non_witness_utxo` whose txid matches the outpoint and whose amount is the one counted (I2); every `Own` output's script is reproduced from the derived key (I3); Σ amounts never wraps (`OVERFLOW` instead); the own-index bound is respected | the 54 vectors' `psbt_hex` | P0 |
| F8 | `judge(state, classified, witness)` and the window charge | structured transactions from F7 against fixture states with `arbitrary` windows/caps/heights/frozen/armed flags and optional witness tokens | §1.4: `Accept` ⇒ per-class per-tx caps, window caps, `fee_abs`/`fee_rate`/fee-window, gap, `maxTipLag`; the charge equals the accepted amounts and never decreases a window; `Refuse` carries ≥ 1 reason; frozen/expired/unarmed/stale ⇒ never `Accept`; `disarms` only on the rollback-suspected reasons | the vectors (accept and refuse) | P0 |
| F9 | `encoding::Dec` primitives (`bytes`, `str`, `list`, `option` with bounds), `Receipt::decode/encode`, `bip39` (entropy ↔ mnemonic ↔ seed) | raw bytes | bounds honoured (a length above the bound is `DecodeError`, never an allocation); round trips; a mnemonic with a bad checksum is refused | — | P0 |
| F10 | `rcore::ops::dispatch(op, input)` under `nosgx,test-init` — the whole ecall surface | (a) arbitrary `op` + arbitrary bytes, incl. an arbitrary "sealed blob" (⇒ `STATE_UNSEALABLE`, never a panic); (b) **sequences**: `TEST_INIT` with a fixed seed, then `arbitrary`-chosen op/payload steps where payloads are honest encodings with mutations, `session::reset()` per sequence | every `Response` decodes; a blob changes only through a `Fresh` op (C-R9-C table is the oracle); `SIGN` returns a signature only for a PSBT the preceding `JUDGE` path accepts, and then `seq` advances by exactly one; after a `TPM`-bound state, every `Fresh` op without a deposited proof is `TPM_REQUIRED`; `Envelope::unseal` and `recovery::decrypt` return `None` on every mutation | the replay smoke (`replay::smoke`) transcript | P1 |
| F11 | owner-cli `piv_attest::verify(slot_der, f9_der, serial, pk)` (`x509-cert`/`der`/`rsa` on bytes the host relays from the YubiKey) and `pem_certs` | raw DER / PEM | never `Ok` on a mutation of a valid chain; no panic in the DER walk (`der_integer_u32`, `ext`) | the test certificates in owner-cli's tests | P2 |
| F12 | owner-cli `attest`: the DCAP quote path (`dcap-qvl` on `quote_hex`) and `IdentityCard::decode` + card signature | raw quote bytes, raw card bytes | never "verified" on a mutated quote or card; no panic (the quote is bytes the node chose) | a quote captured on T2 (the owner's `quote` output file, public data) | P2 |
| — | `signerd` request parsing, `tpm_tss.rs` response handling | — | **not planned**: `signerd` is untrusted by design (THREAT-MODEL); its robustness is availability of our own daemon only. Revisit if a cheap target falls out of F10 | — | P3 |

Rows F1–F9 are `signer-core` only; F10 adds `rcore` (`nosgx`); F11–F12 are the owner's trust domain. The C#
plugin is out of reach of this toolchain and stays with its e2e vectors.

## 3. Harness: engine, layout, rules

- **Engine:** `cargo-fuzz` (libFuzzer) with `arbitrary` for the structured targets. A fuzz crate at the repo root,
  `fuzz/`, **outside** every workspace that ships: `signer-core`'s `Cargo.toml`/`Cargo.lock` are untouched (the
  TCB and `core/PROVENANCE.md` do not move); `libfuzzer-sys`/`arbitrary` exist only in `fuzz/Cargo.toml`.
- **Toolchain:** the fuzz crate carries its own `fuzz/rust-toolchain.toml` pinning a **nightly by date** (libFuzzer
  instrumentation needs it). The repo-root pin stays `1.92.0` for every gate, and nothing built from `fuzz/` is ever
  shipped or measured. The enclave build recipe (`docker/`, `enclave/Makefile`) does not see `fuzz/`.
- **One body, two runners.** Every target's body is a plain `pub fn <target>(data: &[u8])` in `fuzz/src/lib.rs`.
  The libFuzzer binaries in `fuzz/fuzz_targets/` call them; a `cargo test` in the fuzz crate on **stable 1.92.0**
  replays `fuzz/corpus/<target>/*` and `fuzz/regressions/<target>/*` through the same bodies. That replay is the CI
  gate (seconds, no nightly, no sanitizer); the long runs are where the fuzzer finds things.
- **Fixtures.** The structured targets reuse `core/tests/common/mod.rs` (test wallets with the throwaway seeds
  `[0x01; 32]`/`[0x02; 32]`/`[0x77; 32]`, `base_mandate`, `init_state`, `build_psbt`) by `#[path]` inclusion from
  `fuzz/` — zero change to `core/`. If the auditor prefers a dev-only `core/testkit` crate instead, that is a
  one-move change to the `core/` tree (not to the `signer-core` crate) and goes into the impl REQ.
- **Limits per target:** `-max_len` from `proto` bounds; `-timeout=10`, `-rss_limit_mb=1024`, `-malloc_limit_mb`
  below the proto bound — an untrusted length that drives an allocation is itself a finding (DoS lever).
- **Dictionary:** `fuzz/dict/` with the magic constants (wire versions, `TPM_GENERATED`, `TPM_ST_ATTEST_NV`, op codes,
  the domain strings) so the fuzzer passes the first tag checks in minutes, not hours.
- **Corpus policy:** seeds from §2 committed under `fuzz/corpus/<target>/`; minimised with `cargo fuzz cmin` before a
  commit; target < 1 MB total. A new corpus from a long run is **committed by a person after review**, never by CI
  (everything on `main` is public at once since 2026-11-20; a bot writing `main` is not wanted).
- **Findings path:** a crash reproducer is committed to `fuzz/regressions/<target>/REG-<date>-<n>` *before* the fix
  and stays forever; the fix in `core/` or `rcore` is an impl REQ to the auditor (IMPL-PASS before merge, hard rule
  1); a core fix changes MRENCLAVE, so it rides the next ceremony build and is labelled until then (hard rule 4).
  A finding is reported with the reproducer bytes and the oracle that fired; no "fixed quietly".
- **Coverage report:** `cargo fuzz coverage` + `llvm-cov` once per phase, listing which `decode`/`parse`/`verify`/
  `apply` functions the fuzzers reach; attached to the impl REQ as evidence, not as a target to game.

## 4. Where it runs

- **Laptop** (20 cores, the dev's own): development and the long runs (`-jobs`/`-workers`; hours per target for the
  P0 set). Fuzzing is host-side `std` code and needs no SGX, so **nothing runs on the shared Hetzner box or the
  Azure node** — no CPU taken from other projects, no owner's word needed for infrastructure. The fuzz `target/`
  joins the parking routine's enumerated debug-profile list.
- **CI (GitHub Actions, standard runners — free for a public repository):**
  1. `fuzz-replay` — on every push and PR, stable `1.92.0`, replays corpus + regressions through `cargo test` in
     `fuzz/`. **Gate** (red blocks the merge, like `ci.yml`'s jobs).
  2. `fuzz-smoke` — on PRs, pinned nightly, `cargo fuzz run <target> -- -max_total_time=60` per target, whole job
     time-boxed to ~10 min. Advisory first, gate once it has run green for a week.
  3. `fuzz-weekly` — `schedule:`, one hour per P0 target, the new corpus and any artifacts uploaded as a **workflow
     artifact** for a person to review (§3 corpus policy).
- Recommended default: all three; the owner's call on (2) and (3) if CI noise is a concern. Both are cheap to drop.

## 5. Phases

| Phase | Deliverable | Gate |
|---|---|---|
| 0 | this REQ: target list, oracles, layout | DESIGN-PASS (or CONDITIONAL with the auditor's oracle corrections) |
| 1 (~1 day) | `fuzz/` crate; F1, F2, F3, F5, F9 (raw-byte decoders); seeds from the vectors; dictionaries; `fuzz-replay` + `fuzz-smoke` jobs; first ≥ 1 h laptop run per target; evidence file | impl REQ → IMPL-PASS (the harness is test code, but the auditor rules whether the oracles are the ones agreed) |
| 2 (~1–2 days) | structured F4, F6, F7, F8 with the §1.4 invariants; F10 dispatcher sequences under `nosgx`; coverage report; `fuzz-weekly` | impl REQ addendum |
| 3 (later) | F11–F12 (owner-cli), `core/testkit` if ruled, differential header validation against a local regtest Core if ever wanted (not against the shared signet node: D5 limits its RPC to four read calls) | — |

Effort is dev time on the laptop; no spend, no infrastructure, no change to the enclave or its build.

## 6. Questions to the auditor

1. **Oracle set.** Are §1.2–§1.4 the invariants you want evidence for, and is anything missing that the vectors
   do not already pin (candidates: `compare`'s tightening classifier symmetry; the `disarms` set; the C-R9-C
   `Fresh`/`Stale`/`NoBlob` table as the oracle for F10)?
2. **F10 scope.** Sequence fuzzing of the dispatcher under `nosgx` re-implements, in the harness, "what the blob may
   do between two ops". Is the C-R9-C table plus "SIGN ⇒ JUDGE accepted ⇒ seq + 1" the right level, or do you want
   the state machine of DESIGN §3/§6 (pending owner, timelocks, windows) encoded as a model to compare against?
3. **Fixtures.** `#[path]` inclusion of `core/tests/common/mod.rs` (zero change to `core/`) vs a dev-only
   `core/testkit` crate (cleaner, a move inside the `core/` tree). Your preference.
4. **Evidence form.** For the impl REQ: corpus sizes, run times, coverage per function, zero crashes — plus the
   regression files of anything found. Anything else you want to see firsthand (a reproducer you run yourself)?
5. **Standing.** Should "fuzz-replay green" join the per-round IMPL-PASS bar for every future `core/` change, the
   way `cargo test` and the vectors do?
