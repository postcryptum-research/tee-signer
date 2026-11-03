# Decisions log

Owner decisions and dev decisions delegated by the owner, dated. A decision here is binding for
the design of record; the design documents are updated to match at the next unpinned moment (the
auditor rules on pinned hashes, so a pinned file is edited only after its RESP lands).

| Date | # | Decision | By | Folded into |
|---|---|---|---|---|
| 2026-11-03 | D1 | Repository: `github.com/77ph/BTCPayTEE` (working name in the docs stays `tee-signer` until the owner names the product) | owner | this commit |
| 2026-11-03 | D2 | The question "does the stack hold an Intel LE-whitelisted production signing key?" is a **deployment** question, not a development one: this is a single-user TEE for an SMB deployment, and no answer changes what is built. For development the T1 box runs debug enclaves by hardware necessity; the T1 label stands as written; no whitelisted key is assumed anywhere | owner | `THREAT-MODEL.md §3`, `REQ-design §2 R1` — auditor: factual item **closed by owner, out of scope**; R1 stands |
| 2026-11-03 | D3 | Owner key for v1: **any `hw-signer` backend** — YubiKey PIV, TPM 2.0 (Linux, e.g. the owner's laptop), Windows TPM, Apple Secure Enclave, TROPIC01 — **and an encrypted key file is acceptable too, provided it is never on the BTCPay box** (the TPM_sign `KEY_POLICY.md` rule-5 shape: memory-hard KDF + AEAD, passphrase typed at use, decrypted off the box). Hardware is preferred; the file is the floor, not the recommendation | owner | `DESIGN.md §7`, `THREAT-MODEL.md §5` (edit after RESP-design) |
| 2026-11-03 | D4 | BTCPay integration: **plugin, no fork** (seam option B); wallet cold in BTCPay; PayJoin out of v1; `IOnChainSigner` as a later upstream proposal | dev (delegated by owner: "оставляю тебе на решение") | `DESIGN.md §9` (already written so) |
| 2026-11-03 | D5 | Header feed on the dev host: **use the shared nodes already on the server** — the trust-bridge `bitcoind -signet` (RPC `127.0.0.1:10810`, cookie auth, datadir `~/trust-bridge/btc-signet`) read-only for headers; no new chain daemon unless a configuration the shared node cannot give is needed. Never that project's wallet; RPC calls limited to `getblockchaininfo`, `getblockhash`, `getblockheader`, `getbestblockhash` | owner ("если можно использовать общие ноды на сервере было бы идеально") | `deploy/README.md` (edit after RESP-design) |
