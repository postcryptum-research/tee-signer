# REQ — R8 IMPL: no tunnel — the owner's steps as files

**Date:** 2026-11-05 · **Branch:** `r8-no-tunnel` (on top of `main` @ `b569c10`, R7 merged) ·
**Scope:** host side only (`host/signerd`, `owner/owner-cli`, the compose fragments, the docs). No
`core/` or `enclave/` change: the enclave never sees a transport — every owner action is a
self-contained signed message, and that is what makes this round possible. **Asks:** IMPL-PASS
on the properties below; the owner's direction (2026-11-05): "I want everything to work WITHOUT a
tunnel; it makes it clear where one party's work ends", "do it on the laptop → carry it by any
means → run it on the server", "files between machines by scp; ssh is never used to pull a remote
process's output, only output to files".

## 1. The shape

Three places: the **laptop** (owner key, recovery key, `owner-cli`), the **server** (BTCPay, the
sidecar, `signerd`), and an **exchange directory** on each side (`~/tee-owner/exchange/`,
`~/tee-signer-exchange/` = `/exchange` in the sidecar). Nothing crosses but files.

| Where | Command | In | Out |
|---|---|---|---|
| server | `signerd status --state-dir … --out F` | — | the daemon's `/v1/status` JSON |
| server | `signerd init --state-dir … --network N --owner-pk-file F --recovery-pk-file F --out F` | two public keys (files) | the `/v1/init` answer (card, blob, xpub) |
| server | `signerd quote --state-dir … --nonce-file F --out F` | the owner's nonce (file) | the `/v1/quote` answer |
| server | `signerd submit --state-dir … --file F --out F` | a signed owner message (hex file) | the enclave's answer; `PolicyUpdate` at nonce 0 is routed to `/v1/install`, everything else to `/v1/message` |
| server | `signerd policy --state-dir … --out F` | — | the installed (and pending) mandate |
| server | `signerd freeze --state-dir … --out F` | — | the unsigned freeze (the operator's emergency brake) |
| laptop | `owner-cli --status-file F --out F <policy-sign\|cancel\|unfreeze\|rearm\|rotate-owner\|recover\|arm\|witness-token> …` | the carried status (enclave id, nonce, seq, boot challenge) | the signed message as a hex file; **nothing is sent** |
| laptop | `owner-cli init --response F [--quote F --nonce-file F] …` | the carried init answer (and the carried quote) | `wallet.json`; the T2 verifier runs on the carried quote against the owner's own nonce |
| laptop | `owner-cli attest --replay F --nonce-file F …` | a carried quote | the seven checks, offline |
| laptop | `owner-cli policy-show --installed-file F --json F` | the carried installed mandate | the field-by-field diff |

Every server command writes `{"http_status", "ok", "response"}` and exits 1 on a refusal, so a
refusal travels to the laptop exactly as the enclave said it; `owner-cli` unwraps that envelope and
refuses to proceed on a recorded refusal. The old HTTP path (`--signerd`/`--token`) stays for
developers and for the plugin, which lives inside the stack's network; it is not the operator path.

## 2. Properties the auditor is asked to check

1. **The owner key never meets the server, and nothing on the laptop opens a socket to it.** With
   `--status-file`, `Signerd::get` returns the file for `/v1/status` and **refuses every other
   path**; `Signerd::post` refuses outright ("no tunnel"). `init --response` and `attest --replay
   --nonce-file` construct an offline client (`offline: Some(Null)`) that cannot be used for a request.
2. **WYSIWYS is unchanged.** `policy-sign` prints every field and signs the canonical bytes exactly
   as before; the only change is where the bytes go (`--out`).
3. **The nonce for a carried quote is the owner's.** `attest_record` takes `nonce_hex`; with it, the
   quote file must bind *that* nonce at step 6 (the same check as live); without it, `--replay` stays
   the negative vector (a saved quote against a fresh random nonce must fail).
4. **R7 in file mode keeps its order.** `arm` reads the wallet record **before** reading the status
   file, so the comparison is against what the owner saw earlier; the file-mode `arm` cannot confirm
   `boot_armed` itself and says so (the next carried status does).
5. **The server tool is as dumb as the daemon.** `signerd submit` decodes the message only to pick
   the route (`/v1/install` for a nonce-0 `PolicyUpdate`); it cannot sign, cannot alter, and the
   enclave re-verifies everything. The token it uses is the daemon's own, read from the state
   directory on the same machine.
6. **No shell substitutions in the operator text.** File-valued flags (`--owner-pk-file`,
   `--recovery-pk-file`, `--nonce-file`, `--status-file`, `--installed-file`, `--response`,
   `--quote`) exist so the documented commands carry no `$(…)`, no variables.

## 3. Evidence — `scripts/e2e-no-tunnel.sh` (T0, two directories as two machines, 2026-11-05)

keys on the "laptop" → public keys carried → `signerd init` on the "server" writes the answer →
carried → `owner-cli init --response` verifies and writes the record (TOFU on T0), `recovery-verify`
OK → `signerd status` → carried → `policy-sign --out` → carried → `signerd submit` → `installed,
nonce 0, boot_armed True` → `signerd policy` → carried → `policy-show --installed-file` shows the
DIFF and the classification → **restart** → `signerd status` → `boot_armed False`, a fresh
challenge → carried → `arm --out` (record read first; "enclave remembers seq 0; you last saw seq
0") → carried → `signerd submit` → `boot_armed True, nonce 1` → **negative**: the same arm file
again → `POLICY_NONCE`; a restart then the old arm file → refused → `signerd freeze` → carried
status → `arm` (the new load) → `unfreeze --out` → carried → submit → `frozen False, boot_armed
True, nonce 3`. `e2e-no-tunnel: OK`. owner-cli 13/13 tests, clippy clean on both tools.

The T2 quote path (`signerd quote` → `init --quote --nonce-file` / `attest --replay --nonce-file`)
is exercised on the live node after the YubiKey part-2 evidence (C-R7-13); on T0 no quote exists.

## 4. Docs

`docs/FAQ.md` / `FAQ_ru.md` setups 1–2 and the day-to-day and emergency answers are rewritten in
this shape (explicit paths, `cd owner/owner-cli/target/debug` + `./owner-cli`, `scp` for every
carry, every server command `--out` a file); `deploy/README.md` has the exchange directory. The
plugin's status page as the carrier (status shown, signed answer pasted) is named as the next step,
not claimed.
