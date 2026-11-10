# Incident note — the laptop's `.local/` was mirrored to the shared build host (2026-11-03 … 2026-11-10)

**What happened.** `scripts/sync-to-sgx.sh` rsyncs the working tree to `~/tee-signer/` on the Hetzner
build host (shared with the owner's other projects; the T1 dev BTCPay stack runs there). It excluded
`target` and `.git` but not the gitignored `.local/`, so every sync since 2026-11-03 mirrored the
laptop's `.local/` to the box. Found 2026-11-10 while preparing the C-R7-13 deployment, before the sync
of that day.

**What was on the box (encrypted material only; passphrases never left the laptop or the session):**

| Path (under `~/tee-signer/.local/`) | What | Protection |
|---|---|---|
| `ceremony/enclave-ceremony.pem` | the **dev** ceremony enclave-signing key (RSA-3072, MRSIGNER `56b25ccb…`) | PEM encrypted AES-256, passphrase |
| `signet/owner.key`, `signet/recovery.key` | the T1 dev wallet's keyfile owner (retired on T2, still the T1 dev owner) and the recovery key shared by the dev wallets | scrypt + AES-GCM keyfiles, passphrase |
| `signet-t2/witness.key`, `t0-piv/file-owner.key`, `t0-piv/recovery.key` | dev witness key; T0 throwaway keys | same keyfile format |
| `signet/token`, `signet-t2/token`, `t0-piv/state/token` | signerd bearer tokens (loopback services; not a secret in the threat model) | — |
| `signet/wallet.json`, `signet-t2/wallet.json`, `t0-piv/wallet.json`, `t0-piv/state/state.sealed`, attestations, mandates, monitor journals, PSBTs, `piv-9a-attest/*` | records (public data + recovery blobs encrypted to the recovery key), T0 sealed state (nosgx stand-in), public attestation material | public / encrypted to the recovery key |
| `signet/hetzner-node.cookie` | a copy of the box's own signet node RPC cookie | already lives on that box |

Not affected: the TPM owner key (non-exportable, laptop TPM), the YubiKey owner key (non-exportable,
slot `9a`), the production T2 node (its `~/tee-signer/` holds only `btcpay/` and the token).

**Why it matters (honestly labeled).** Rule: the owner key is never on the BTCPay box and the ceremony
key is offline. Both were violated for the **dev** material, in encrypted form, on a machine where
root is the owner. Nobody outside the owner's own account had access as far as we know; the files
were readable only by the user `andrey`. An attacker with that account could have tried the
passphrases offline (scrypt; the passphrases are dev-grade and present in the dev transcripts, which
is the weakest point of this dev setup, not the keyfile format).

**Fix (2026-11-10).** `~/tee-signer/.local` and `~/tee-signer/.claude` removed on the box by their
enumerated paths and verified absent; `scripts/sync-to-sgx.sh` now excludes `.local` and `.claude`;
the resync of the same day confirmed no `.local` on the box. Nothing was ever synced to the T2 node.

**Consequences / decisions for the owner and the auditor.**
- The dev ceremony key is considered *exposed-encrypted*. It signs only dev builds; `init`/`attest`
  pin MRENCLAVE, not only MRSIGNER, so a signature by this key alone does not make a foreign enclave
  pass the owner's check. A product release key is a new ceremony anyway (REQ-r6 §3); the owner
  decides whether the dev key is rotated now or at that ceremony.
- The T1 dev wallet's keyfile owner is *exposed-encrypted*; the T1 wallet is signet and is being
  re-initialised for the R7 drill (C-R7-12) with a fresh owner key anyway.
- The dev recovery key (`signet/recovery.key`) protects the recovery blobs of the dev wallets; the
  T2 re-init of 2026-11-10 (C-R7-13) was about to reuse it. Decision taken for the drill: generate a
  **fresh recovery key** for the new T2 wallet instead (see REQ-r7 impl §4), so the production-tier
  record does not rest on exposed material.

**Closure of the auditor's two gaps (same day).**
- *Where are the passphrases?* Only in this laptop's Claude Code transcripts and memory directory
  (`~/.claude/projects/-home-andrey-llm-btcpay-tee/`), outside the repo tree; a grep of the whole repo
  tree for every dev passphrase string finds none. The box therefore only ever held encrypted blobs,
  never a passphrase — the blobs stay encrypted-safe (auditor: severity low).
- *Bearer tokens that sat on the box are live credentials.* T1 sidecar token **rotated** (file
  removed inside the container, sidecar restarted, new token minted; old token → `401`, new → `200`;
  the T1 BTCPay plugin re-pointed through its settings API, status page green; laptop copy
  replaced). T0 stale token file deleted (daemon stopped; a start mints a new one). T2: the old token
  leaves with the re-init of 2026-11-10 (the sidecar mints a new one on an empty state directory);
  the `401` of the old token on the node is recorded in REQ-r7 impl §4.1 when the owner's server
  step is done.
- *Dev ceremony key rotation now vs at the release ceremony:* the owner's decision, pending
  (auditor's assessment: low urgency — never paired with its passphrase on the box, MRENCLAVE pin
  bounds a signature by it).

**Owner's ruling (2026-11-10, same day):** «не проблема … главное не в репозиторий» — the mirrored
`.local/` on the owner's own shared build host is accepted; what matters is that nothing of it was
ever in git (it never was: `.local/` is gitignored). No rotation of the dev ceremony key. Incident
closed with the fixes above (sync exclusion, removal, token rotation).
