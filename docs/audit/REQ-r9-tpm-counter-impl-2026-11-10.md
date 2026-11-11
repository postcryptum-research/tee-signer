# REQ-r9 — the TPM counter as the enclave's freshness source (IMPL) — 2026-11-10

**Round:** R9, implementation. **Design of record:** `REQ-r9-tpm-counter-design-2026-11-10.md`,
**DESIGN-PASS** `RESP-r9-tpm-counter-design-2026-11-10.md` (six pinned answers, must-holds A–E).
**Branch:** `r9-tpm` (not merged; merges only on IMPL-PASS). **Asked:** IMPL-PASS on the source,
with the deployment facet carried (no TPM in front of any node yet).

## 1. What was built (per file, each line gateable)

`core/` — pure, `no_std`, **no new crate** (`p256` and `sha2` were already in the TCB):
- `src/tpm_attest.rs` (new): `TpmAnchor { ak_pk, nv_name[34], expected }` with `well_formed()`;
  `parse_nv_attest()` — the fixed-layout `TPMS_ATTEST`/`TPMS_NV_CERTIFY_INFO` reader over a
  bounds-checked big-endian cursor (every read returns `None` past the end → `TPM_PARSE`; magic,
  type, `extraData` length, index Name length, `offset == 0`, `nvContents == 8`, `safe ≤ 1`, no
  trailing bytes; no allocation, no loop, no arithmetic that can wrap — `#![deny(arithmetic_side_effects)]`
  holds); `verify_nv_certify()` — parse → nonce → index → P-256 signature over `SHA-256(attest)` →
  `counter == expected`, each step its own reason; `build_nv_attest()` — the honest encoder for the
  stand-in and the tests (never called by the enclave).
- `src/state.rs`: `State.tpm: Option<TpmAnchor>`; **the state version is the anchor's presence** —
  `STATE_VERSION 1` = unanchored (every pre-R9 blob and the R1 vectors decode unchanged),
  `STATE_VERSION_TPM 2` = anchored, with the anchor's three fields after `seq`; one encoding per
  value, strict decode kept. `bump_tpm()` — the **one** `+1`, saturating (C-R9-B). `apply_anchor()` —
  the `apply_arm` checks (owner signature, enclave id, next nonce consumed, this load's challenge,
  `seq_seen ≤ seq`) plus `well_formed()`, then `tpm := Some(anchor with expected = counter)`.
  `apply_message` refuses `Anchor` like `Arm` (both go through their own path).
- `src/update.rs`: `Message::Anchor { enclave_id, nonce, boot_challenge, ak_pk, nv_name, counter, seq_seen, sig }`,
  `TAG_ANCHOR = 9`, domain `tee-signer/anchor/v1`, payload/sig/enclave_id/encode/decode arms.
- `src/reason.rs`: `TPM_REQUIRED`, `TPM_PARSE`, `TPM_NONCE`, `TPM_INDEX`, `TPM_SIG`, `STATE_STALE`.
- `src/proto.rs`: `op::TPM_NONCE = 11`, `op::TPM_PROOF = 12`, `TpmProof { attest ≤ 512 B, sig[64] }`;
  `StatusResponse` + `tpm_bound`, `tpm_expected`, `tpm_last_fresh`.
- `tests/tpm_attest.rs` (new, 7 tests): honest proof → counter; stale either way → `STATE_STALE`;
  replay → `TPM_NONCE`; foreign index → `TPM_INDEX`; foreign key and a flipped signature bit →
  `TPM_SIG`; **every truncation length, a trailing byte, overlong, wrong magic/type/offset/contents
  length** → `TPM_PARSE` with no panic; a wrong nonce *length* → `TPM_NONCE`; a mutated-but-well-formed
  attest → `TPM_SIG` (the signature, not the parser); `well_formed` matrix (C-R9-A).

`enclave/rcore/`:
- `src/session.rs`: volatile `TPM_NONCE` (4 words) + `TPM_NONCE_LIVE`, the deposited proof
  (`[AtomicU64; 72]` = 576 B) + length + `PRESENT`, `TPM_LAST_FRESH`. `tpm_nonce_issue()` draws 32
  bytes from `sgx_read_rand`, **forgets the previous nonce and any proof** (exactly one live nonce,
  RESP-r9 Q5); `tpm_proof_store()` refuses without a live nonce; `tpm_proof_take()` consumes nonce
  and proof together, whatever the verdict follows. `reset()` (test builds) clears all of it.
- `src/ops.rs`: `FRESHNESS` table + `Freshness { Fresh, Stale, NoBlob }` classifying **every** op code
  (C-R9-C), with the unit test `freshness_table_is_complete` (a new op in `proto::op` not listed here
  fails it; a listed op that does not exist fails it; the Fresh/Stale assignment is asserted).
  `open_full_fresh()` — the one helper every state-changing or signing op calls: when `state.tpm` is
  set it takes the deposited proof (`TPM_REQUIRED` if none), decodes it (`TPM_PARSE`), verifies it
  against the blob's anchor and the live nonce, records `last_fresh`, and on success calls
  `session::arm()` — **auto-arm strictly on `counter == expected`** (RESP-r9 Q4). `open_full_stale()`
  for `POLICY` (and `STATUS`/`REPORT` keep `open`): pure reads, no proof. `seal_or(&mut env)` — the
  **one** seal helper, bumps before sealing (C-R9-B); every caller changed to pass `&mut`.
  `tpm_nonce` / `tpm_proof` ops. `apply_message`: `Anchor` → `apply_anchor(&msg, &challenge)`, arms on
  success like `Arm`; and — **a design precision found by the e2e rollback drill, §4** — the `Anchor`
  opens the blob with `open_full_stale`: it is the attended override for a counter mismatch, so it
  cannot itself demand the proof it exists to replace; its own bindings (owner signature, next nonce,
  this load's challenge, `seq_seen`) stand in. Every other message goes through `open_full_fresh`.
  `status`: the three new fields.
- `tests/replay.rs`: `tpm_counter_freshness_r9` — the T0 scenario of §3.

`host/signerd/` (untrusted):
- `src/tpm.rs` (new): `TpmTransport { describe, info, certify(nonce), increment }`; `SoftwareTpm`
  (a P-256 key, a SHA-256 Name and a counter in a 0600 file; `SIGNERD_TPM_LIE=stale|nonce|sig|index|parse`
  makes it lie one way — the e2e negatives); `RemoteTpm` (a 60-line HTTP/1.1 client over `std::net`
  for the dev agent: `GET /info`, `POST /certify`, `POST /increment`; `http://` only — loopback or a
  tunnel); `from_env()` reads `SIGNERD_TPM=software:<file>|remote:<url>`.
- `src/main.rs`: `Daemon.tpm`; `call_fresh()` — nonce → `certify` → deposit → the call, for
  `INSTALL`, `APPLY_MESSAGE`, `FREEZE`, `HEADERS` (×3 call sites), `JUDGE`, `SIGN` (never for
  `STATUS`/`POLICY`/`REPORT`/`INIT`); `persist()` increments **after** the blob is durable and logs an
  error if the increment fails (the next call is `STATE_STALE` — a pause until the owner anchors);
  `StatusJson` + `tpm_bound`, `tpm_expected`, `tpm_last_fresh`, `tpm_transport`; `GET /v1/tpm/info`,
  `GET /v1/tpm/certify?nonce=`; R8 file subcommands `tpm-info --out`, `tpm-certify --nonce-file --out`;
  `h_freeze` now surfaces a refusal with its reasons (it had only `decode` before — a refused freeze
  did not exist until `STATE_STALE`).

`owner/owner-cli/`:
- `anchor --key <locator> (--tpm-info-file F | --ak-pk-file F --nv-name-file F) --proof-file F --proof-nonce-file F [--i-have-investigated]`
  with the globals `--wallet-record`, `--status-file`/`--out`: reads the record first (the sequence the
  owner saw), **verifies the certify proof itself** — parses the attest, checks the signature under the
  AK the owner is about to pin, the Name and the owner's own nonce — and takes the counter from it
  (C-R9-D; a refused proof stops the command: "do not anchor"); then the `Arm` bindings (challenge,
  `seq_seen`, the rollback warning and `--i-have-investigated` logging), signs `Message::Anchor`,
  submits or writes `--out`.

`scripts/e2e-local.sh`: the R9 segment (§4).

## 2. The six pinned answers and the must-holds, in the code

| Pin | Where |
|---|---|
| Q1 uniform bump | `seal_or` bumps on every seal, `HEADERS` included; the hybrid (`TPMA_NV_ORDERLY`) index is the agent's allocation default — **agent not yet written** (§5) |
| Q2 two messages | `TAG_ARM 8` / `TAG_ANCHOR 9`; `Arm` never touches `state.tpm` |
| Q3 pure reads | `STATUS`, `POLICY`, `REPORT` read without a proof; `tpm_expected` documented as possibly stale; no decision reads it (the enclave decides only in `open_full_fresh`) |
| Q4 auto-arm | `open_full_fresh`: `session::arm()` only after `verify_nv_certify` returned `Ok` (nonce-bound, AK-verified, value equal) — never on absent or stale |
| Q5 no nonce grace | `tpm_nonce_issue` forgets the old nonce and proof; `tpm_proof_take` consumes both; the test proves a proof for an earlier nonce → `TPM_NONCE` and a consumed proof → `TPM_REQUIRED` |
| Q6 agent scope | not built this round (§5); the `RemoteTpm` client is `http://` only |
| A parser | `tpm_attest.rs` + `tests/tpm_attest.rs` (truncation at every length, no panic) |
| B one bump | `State::bump_tpm` called from `seal_or` only (`grep bump_tpm` → two sites: the definition and the helper) |
| C completeness | `FRESHNESS` + `freshness_table_is_complete`; the `Anchor` exemption is explicit in the table's comment and in `apply_message` |
| D attested counter | `owner-cli anchor` verifies the proof and takes the counter from it; `tpm-info` is used only for the key and the Name |
| E agent isolation | carried with the agent (§5) |

## 3. T0 evidence — `enclave/rcore/tests/replay.rs::tpm_counter_freshness_r9`

An unanchored wallet behaves as R7 (`tpm_bound false`). Anchor negatives: wrong challenge →
`ARM_CHALLENGE`; `seq_seen` ahead → `ARM_SEQ_BEHIND`; a SHA-1 Name → `POLICY_INVALID`; wrong nonce →
`POLICY_NONCE`; the recovery key → `POLICY_SIG`. The genuine Anchor at live counter 1000 → the blob
expects 1001 after the seal. Then: `FREEZE` without a proof → `TPM_REQUIRED`; `POLICY` reads without
one; a proof deposited without a live nonce → `TPM_NONCE`; an honest proof → `FREEZE` applied, expects
1002, `tpm_last_fresh`; the same op again → `TPM_REQUIRED` (consumed). **Rollback:** the pre-freeze blob
(expects 1001) against a TPM at 1002 → `STATE_STALE`; **crash between seal and increment** (blob
1002, counter 1001) → `STATE_STALE`. **Replay** of an earlier nonce's proof → `TPM_NONCE`. Foreign AK →
`TPM_SIG`; foreign Name → `TPM_INDEX`; truncated attest → `TPM_PARSE`; the proof consumed after the
refusal → `TPM_REQUIRED`. **Unattended reload:** `boot_armed false`; an owner `Unfreeze` without a
proof → `TPM_REQUIRED` (not `NOT_ARMED`); with a fresh proof → applied and **`boot_armed true`
without any Arm**. **Reload onto the rolled-back blob:** `STATE_STALE`, never armed; an `Unfreeze`
with a proof still `STATE_STALE`; the owner's **`Anchor` on the stale blob without a proof** →
applied, expects the live counter, armed; a proven `FREEZE` then goes through; the captured Anchor
replayed → `POLICY_NONCE`.

## 4. T0 evidence — `scripts/e2e-local.sh` (two processes: the owner's tool and the daemon with `SIGNERD_TPM=software:…`)

After the R7 segment: the daemon restarts with a transport, the state is unanchored (`tpm_bound false`);
`signerd tpm-info --out`, a nonce from `openssl rand`, `signerd tpm-certify --nonce-file --out`,
`owner-cli anchor --tpm-info-file --proof-file --proof-nonce-file` → `attested counter: 1`, applied,
`tpm_bound true, tpm_expected 2`. `freeze`/`unfreeze` → `tpm_expected 4`, `tpm_last_fresh true` (the
daemon did nonce → certify → deposit → call each time and incremented after each persist).
**Unattended restart:** `boot_armed false`; one `freeze` → `boot_armed true` with no owner. **Rollback
drill:** `state.sealed` copied, two more seals, the daemon stopped, the old file put back, restarted →
`freeze` refused `STATE_STALE`, `boot_armed false`, `tpm_last_fresh false`; **this is where the first
version refused the owner's `Anchor` too** (`422 STATE_STALE`): the override was going through
`open_full_fresh`. Fixed by the §1 precision; the owner's `anchor` with a fresh `tpm-certify` → applied,
`tpm_expected 9`, armed. **Five lying transports** (`SIGNERD_TPM_LIE=stale|sig|nonce|index|parse`),
each on a restarted daemon → `freeze` refused `STATE_STALE` / `TPM_SIG` / `TPM_NONCE` / `TPM_INDEX` /
`TPM_PARSE`. Honest transport again → normal. `e2e-local: OK (incl. REQ-r9 TPM counter)`.

Gates: `cargo test` green in `core` (incl. the R1 vectors through the dispatcher), `rcore`
(`nosgx,test-init`), `signerd` (`nosgx`), `owner-cli`; `clippy -D warnings` clean in `rcore`,
`signerd`, `owner-cli`; in `core` the findings are the three that main already has (`bip39.rs` ×2,
`lib.rs` ×1) — none in the new or touched code. `cargo fmt --check` fails repo-wide on this toolchain
already on `main` (286 diffs); the two new core files are rustfmt-clean.

## 5. Not in this round (carried, stated)

- **The dev agent** (`tee-tpm-agent`, the owner's laptop TPM through `tss-esapi`) — **frozen by the owner
  on 2026-11-10** («замораживаем идею»). The product path is a TPM in front of the node:
  [issue #1](https://github.com/77ph/BTCPayTEE/issues/1) (a vTPM via Azure Trusted Launch on `sgx-node-3`,
  or a +1 counter VM) or the operator's own server with a physical TPM. The `RemoteTpm` client stays for
  the +1-VM option; must-hold E and Q6 apply to that agent when it is written.
- ~~The `tss` transport for a local `/dev/tpmrm0` (the product path) — when a node has a TPM.~~ **Written
  2026-11-11, §7 below** (the owner's «делай на свой выбор», item 2); it waits for a node with a TPM.
- Hardware builds of this `rcore` (T1 build box; the ceremony signing) and any deployment: the
  project's node has no TPM, so the product claim stays deployment-gated (design §4/§6).
- Operator docs beyond the FAQ note: written when the agent bench has run.
- Anchoring at `init` (design §2 "at `init`"): not implemented — the anchor is set by the `Anchor`
  message right after `install` (one more owner signature at deployment, one fewer code path).

## 6. Questions for the auditor

1. The `Anchor` exemption from the proof (§1, found by the drill): the design's §2.5 implied it
   ("the attended override for every mismatch") but did not say it; please confirm the reading and
   that its bindings are sufficient. The alternative — an Anchor that must carry a proof — makes a
   stale state unrecoverable, which contradicts edge 2 of your pre-review.
2. `POLICY` classified `Stale` (the design named only `STATUS`/`REPORT`): it is a pure read of the
   mandate, no decision; acceptable?
3. The state-version-as-anchor-presence encoding (v1/v2) instead of an `Option` field: keeps the R1
   vectors valid and one encoding per value; acceptable, or do you want a version bump with
   regenerated vectors?

## 7. Addendum 2026-11-11 — the `tss` transport (host side, branch `r9-tss`; your Q6 / C-R9-E lens)

**What:** `host/signerd/src/tpm_tss.rs` (new, ~620 lines incl. tests), `tpm.rs` (`from_env`: the `tss:`
prefix), `main.rs` (`tpm-setup`, `tpm-teardown`, a hex-handle parser), `Cargo.toml` (feature `tss` →
optional `tss-esapi = "7.7"` with the crate's bundled x86_64 bindings, so the build image needs no clang;
links the system libtss2), `scripts/e2e-tss-local.sh` (the laptop run). No `core/` or `enclave/` change.

**Spec:** `SIGNERD_TPM=tss:<tcti>?ak=0x81……&nv=0x01……` — both handles **mandatory** (no default, no probing),
each range-checked (`0x81…` persistent, `0x01…` NV), hex with `0x` only; `<tcti>` empty = `device:/dev/tpmrm0`.

**Handle isolation (your must-hold E, line by line):**
- `tpm-setup --ak-handle --nv-index --out` lists the TPM's handles (`TPM2_GetCapability(HANDLES)` over the
  persistent range, then the NV range) **before creating anything** and refuses either one that is listed
  — `REFUSED: persistent handle 0x81000100 is already in use by another key — never evicted …`. The run
  probed the owner's key `0x81000100` and the EK certificate index `0x01c00002`: both refused, the handle
  lists unchanged (the script diffs them).
- the objects: a `CreatePrimary` under the **owner hierarchy** persisted at `--ak-handle` via
  `EvictControl`, and an `NV_DefineSpace` at `--nv-index`; the first `NV_Increment` initialises the counter
  (an unwritten index can be neither read nor certified).
- `tpm-teardown --ak-handle --nv-index` removes exactly the two named objects, each **only if its public
  area matches `tpm-setup`'s template** (`is_our_ak`: restricted ∧ sign ∧ ¬decrypt ∧ fixedTPM ∧ fixedParent
  ∧ sensitiveDataOrigin ∧ userWithAuth ∧ P-256 ∧ ECDSA/SHA-256; `is_our_counter`: `COUNTER`, 8 bytes,
  authRead ∧ authWrite ∧ noDA ∧ ¬ownerWrite ∧ ¬policyWrite ∧ ¬ppWrite ∧ ¬platformCreate). Probed against the
  owner's key: `REFUSED: the key at 0x81000100 is not a tee-signer attestation key (template differs)`.
  Nothing in the binary knows the laptop's other handles — the guard is the template, not a list.
- the daemon never creates, never evicts: `TssTpm::open` only resolves the two handles
  (`Esys_TR_FromTPMPublic`) and fails with "run `signerd tpm-setup`" when one is missing.

**Your two product notes, implemented:** `SIGNERD_TPM_AUTH=<any string>` → SHA-256 → the authValue of
*both* the key and the index (`CreatePrimary` auth, `NV_DefineSpace` auth; the runtime sets it with
`Esys_TR_SetAuth` and uses password sessions). Unset = empty auth, the isolated-test configuration. The
attestation key is **restricted** on top: a restricted signing key signs only TPM-generated structures
(`TPM_GENERATED` magic), so even with its auth a host cannot obtain its signature over a forged
`TPMS_ATTEST` (`TPM2_Sign` of arbitrary digests is refused by the TPM).

**Why raw ESAPI for the runtime:** `tss-esapi` 7.7.0 has no `nv_certify` (`non_volatile_storage.rs:232`
"Missing function: NV_Certify"). The runtime (`certify`, `increment`, the three reads behind `tpm-info`)
therefore calls `Esys_NV_Certify` / `Esys_NV_Increment` / `Esys_ReadPublic` / `Esys_NV_ReadPublic` /
`Esys_NV_Read` through the crate's `tss2_esys` bindings on an ESAPI context this module owns
(`Tss2_TctiLdr_Initialize` → `Esys_Initialize`, finalized in `Drop`). Every `unsafe` block is annotated;
every ESAPI out-buffer is copied and `Esys_Free`d before the function returns; the `ecdsa` union member is
read only after `sigAlg == TPM2_ALG_ECDSA` and `hash == SHA256` are checked; `r`/`s` are left-padded to 32
and the signature is low-s normalised (the enclave verifier accepts only that half). The one-shot setup /
teardown use the safe `tss_esapi::Context` API (the same idiom as `owner-cli`'s TPM keygen). The
alternative — shelling out to `tpm2_nvcertify` — was rejected: temp files per call and auth values on a
command line.

**`ORDERLY` (your Q1 default, pinned):** the index is hybrid by default, `--no-orderly` makes it plain. On
the laptop's Intel PTT both define fine. Two facts the run surfaced, both now in the docs: (1) a **new
counter does not start at 0** — the TPM seeds it above the last value of any counter ever deleted on it
(the runs saw 1 → 2 → 3 → 6 → 12 → …; only `counter == expected` matters, the absolute value is opaque);
(2) a hybrid counter jumps *forward* after an unorderly shutdown → `STATE_STALE` → owner re-anchor. On a
**virtual** TPM there is no flash to spare and a hard reset of a VM is not rare, so the operator doc
recommends `--no-orderly` there. **Q7 for you:** should `--no-orderly` be the default when the TCTI is a
vTPM, or stay the operator's explicit choice as now? (I prefer explicit: one flag, documented.)

**T0 evidence — `scripts/e2e-tss-local.sh` on the laptop (Intel PTT, `/dev/tpmrm0`, 2026-11-11):**
refusals for an occupied handle and an occupied index (nothing created) → setup at `0x81000200` /
`0x01800200` → a second setup refused → teardown's template guard refused on the owner's key → the nosgx
daemon with `SIGNERD_TPM=tss:…` from the first start, init + install → `tpm-info`, owner nonce,
`tpm-certify` → **a real `TPMS_ATTEST` (149 bytes, magic `ff544347`, type `8014`) through the
fixed-layout parser**, `anchor` accepted (`attested counter: 12 … the state expects counter 13`) →
freeze + unfreeze → `tpm_expected 15 == TPM counter 15` (read back independently through `tpm-info`) →
unattended restart → `boot_armed false` → one call → `boot_armed true, tpm_last_fresh true` → an older
state file restored + restart → `STATE_STALE`, not armed → owner re-anchor (`attested counter: 19 … expects
20`) → teardown → `tpm2_getcap handles-persistent` + `handles-nv-index` **identical to the snapshot taken
before the run**. The script refuses to start when its two handles are occupied and tears down in its exit
trap. Run with `E2E_DIR` in the session scratchpad; nothing left in `/tmp`.

**Not in this addendum:** the T2 image (`btcpay/docker/Dockerfile.signerd-t2`) does not yet carry
libtss2 or the `tss` feature — that change goes with the vTPM (issue #1) so the live T2 stack is not
rebuilt for nothing; `deploy/README.md` lists the exact packages and flags. The remote agent for the
+1-VM option stays unwritten.

**Q8 — answered by the auditor the same day (Name/pubkey match required) and done before the merge:**
`tpm-teardown` now takes `--setup-file` (the JSON `tpm-setup --out` wrote, or a later `tpm-info`) and
refuses unless the key at `--ak-handle` has exactly the recorded public point and the index at
`--nv-index` has exactly the recorded Name — then the template guard, then the removal. No file →
refuse. Probed in the laptop run: the owner's key under `--ak-handle` ("public key differs"), a record
with another Name on our own handles ("its Name differs"), a missing record — each refused with our two
objects still present; the real record then removed them and the handle lists matched the snapshot.

## 8. Addendum 2026-11-11 (evening) — the T2 image recipe with `tss`, prepared and proven, not deployed

Owner's «1 и 2»: (1) the FAQ's file-exchange anchor form is now exercised by `scripts/e2e-tss-local.sh`
(`signerd status --out` → `owner-cli --status-file … --out anchor.msg anchor …` → `signerd submit --file`
→ `tpm_bound: true`, PASSED on the laptop TPM); (2) the image recipe for the product path, branch
`t2-tss-image`, for your image/compose review before any deployment:

| File | Change |
|---|---|
| `docker/Dockerfile.enclave-build` | `pkg-config libtss2-dev` in the first apt layer; daemon `cargo build … --features sgx,tss`; MANIFEST gains `signerd features: sgx,tss` and the `libtss2-dev` version |
| `btcpay/docker/Dockerfile.signerd-t2` | runtime `libtss2-esys-3.0.2-0 libtss2-tctildr0 libtss2-tcti-device0 libtss2-mu0 libtss2-sys1` (jammy 3.2.0-1ubuntu1.1) |
| `btcpay/docker/opt-add-tee-signer-tpm.custom.yml` (new) | opt-in overlay for the sidecar: `/dev/tpmrm0`, `group_add ${TEE_TPM_GID:?}`, `SIGNERD_TPM=${TEE_TPM_SPEC:-tss:device:/dev/tpmrm0?ak=0x81000200&nv=0x01800200}`, `SIGNERD_TPM_AUTH=${TEE_TPM_AUTH:?}` — both `:?` so a forgotten gid or password refuses to start |
| `btcpay/docker/stack.sh` | `gen` copies all `opt-add-tee-signer*.custom.yml` fragments (only the named ones take part) |
| `deploy/README.md`, `docs/FAQ{,_ru}.md`, `docs/ENCLAVE.md` §4c, `docs/DESIGN.md` §10 | the product path spelled out: ceremony + new wallet, one-shot `tpm-setup` before the sidecar, the overlay, the four anchor steps |

**Gate 5 (reproducibility), Hetzner box, 2026-11-11:** the same sources (current `main`) built twice —
`~/tee-signer-out/r9-main-baseline` under the old build image (`tee-signer-build:2.28`, no libtss2) and
`~/tee-signer-out/r9-tss` under the new one (`tee-signer-build:2.28-tss`) — `docker/compare-builds.sh`:
`REPRODUCIBLE: MRENCLAVE c7c5d8ef373b57083034693616b06b2dc0f12b345ee905b8b0d8be8d4f527db0; attributes/mask,
misc, ProdID/SVN identical; enclave.so byte-identical`. Both runs `build+gates: OK` (dev key). So libtss2
changes the daemon only: `signerd` 9.3 MB → 11.5 MB, `tpm-setup --help` answers inside the T2 image, `ldd`
resolves `libtss2-esys/tctildr/mu/sys`. The T2 image built from `r9-tss` under a check tag was removed
again together with its dev-signed tarball (never shipped); the two output directories stay as evidence.

**Compose merge check (box, the generator container in a temp dir of ours, removed):** with
`BTCPAYGEN_ADDITIONAL_FRAGMENTS=opt-save-storage-xxs;opt-add-tee-signer-tpm.custom;opt-add-tee-signer-t2.custom`
the generated `tee-signer` service has the three devices (`sgx_enclave`, `sgx_provision`, `tpmrm0`), the
merged environment incl. `SIGNERD_TPM`/`SIGNERD_TPM_AUTH`, the volumes, and `group_add` — nothing else moved.

**What this means for the product path (stated for the owner too):** `c7c5d8ef…` is the measurement of
current `main`, which has R9 *inside the enclave* (TPM_NONCE/TPM_PROOF ops, the verifier); the live T2
enclave `ca5c1a6a…` predates it. Putting the vTPM in front of the T2 signer is therefore a **new enclave
build** — ceremony-signed (`SIGN=ceremony PHASE=gendata/catsig`, as on 2026-11-10) — **and a new wallet**
(the sealed state does not cross MRENCLAVEs; FAQ "How do I move to a new enclave build"; the owner's
`t2-r7-redeploy.sh` is the worked example). Nothing was loaded on the node; the live stack is untouched.

**Auditor's verdict, same day (verbatim excerpt):** «T2 tss-recipe — ACK / IMPL-PASS firsthand @e9400db. diff
трогает ТОЛЬКО docker/ + btcpay/docker/ + docs — ни одного enclave/core/signerd-source. Строка сборки
ЭНКЛАВА не изменена; изменена только сборка демона (`--features sgx` → `sgx,tss`); libtss2-dev — host build-dep
⇒ enclave.so обязан быть байт-идентичен ⇒ MRENCLAVE неизменен; compare-builds.sh — эмпирическое подтверждение
необходимого свойства. Оверлей fail-closed (`:?` на gid и auth, device-gated). Consequence AFFIRM: vTPM-путь =
новая ceremony-signed сборка + новый кошелёк. Не верил firsthand: сам прогон gate 5 и item 1 — беру на отчёт.
ВЕРДИКТ: мерж t2-tss-image — ACK. Деплоя нет до owner vTPM-шага + моей image/compose-проверки в тот момент.»
Merged to `main` on that ack.

