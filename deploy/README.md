# DEPLOY — isolation plan (shared SGX host)

Build/dev host: `94.130.18.162` (`aatproject`, Hetzner). Shared with the perp DEX, Phoenix,
trust-bridge, ethsigner, rippled, two `bitcoind`s (regtest 18443-18445, testnet4 48332-48334),
PostgreSQL 5432, nginx 80/443. **Survey 2026-11-03, read-only.** Nothing of theirs is touched.

## Host facts (measured 2026-11-03)

| Fact | Value |
|---|---|
| CPU | Xeon E3-1275 v6; **SGX1 only, no FLC**, legacy `/dev/isgx` 2.11; EPC ≈ 94 MiB shared |
| SDK / PSW | `/opt/intel/sgxsdk`, PSW 2.25 (`aesmd` active); gcc 11.4, no clang |
| Launch | **debug only** (`SGX_MODE=HW SGX_DEBUG=1`); production launch impossible without Intel LE whitelist |
| Attestation | **none** (EPID retired 2025-04; DCAP needs FLC) |
| Gramine | 1.8 installed, **cannot run** (needs `/dev/sgx_enclave`) |
| Rust | `~/.cargo` 1.92 stable (1.81/1.85/1.88 also); target x86_64-unknown-linux-gnu only |
| Docker | 24.0.7 (other projects' containers running — never touched) |
| bitcoind | v30.2 present (other projects' instances); we run our own signet node if needed |

## Our allocation (reserve before use; keep current)

| Resource | Value | Status |
|---|---|---|
| directories | `~/btcpay-tee-lab/` (feasibility lab, kept), `~/tee-signer/` (working tree synced by `scripts/sync-to-sgx.sh`), `~/tee-signer-state/` (`pid`, `token`, `state.sealed`, `receipts.jsonl`, `signerd.log`; signet only) | in use since 2026-11-03 |
| ports | `127.0.0.1:7390` signerd API (in use) · `7391-7399` reserved (BTCPay test stack) | 7390 in use |
| processes | `signerd` as user `andrey`, started with `nohup`, pid in `~/tee-signer-state/pid` (no systemd, no sudo); restart: `kill $(cat ~/tee-signer-state/pid)` then the `nohup` line in `scripts/` | running |
| access | from the laptop through `ssh -L 7390:127.0.0.1:7390` only; nothing is exposed on an interface, nothing in nginx | — |
| chain daemons | **none of our own (owner D5, 2026-11-03).** Headers come from the shared trust-bridge `bitcoind -signet`: RPC `127.0.0.1:10810`, cookie auth from its datadir `~/trust-bridge/btc-signet` (same unix user), **read-only RPC subset only**: `getblockchaininfo`, `getbestblockhash`, `getblockhash`, `getblockheader`. Never its wallet, never a write RPC, never its P2P, never its datadir or state. **Co-tenancy rule (auditor):** the enclave does not trust the feed (it verifies PoW from the pinned checkpoint), so a lagging or malicious feed is our own DoS and nothing else; a feed outage is handled as *our* outage and must never couple the two projects (no restarts, no pokes, no shared files). Signet's cheap PoW ⇒ the weak-clock label is shown at `GET /v1/status` on this host. A BTCPay test stack (R3) brings its own `bitcoind` inside its compose project on the reserved ports | decided |

Occupied ports on the host (2026-11-03 `ss -ltn`): 22, 80, 443, 1080-1082, 3001-3003, 3005,
3011-3013, 3015, 4003, 5005-5006, 5015-5016, 5432, 6006-6007, 6016-6017, 7777, 8088, 9085-9089,
10810-10811, 10815, 10840-10847, 13001, 15005-15006, 18232, 18234, 18443-18445, 48332-48334,
51235, 51335. The 739x range is free.

## Rules

- Delete by enumerated paths; verify by the same list. No globs in `~` or `/tmp`.
- No `sudo`, `systemctl`, `docker stop/rm`, `kill` on anything not ours.
- Build with `make -j4` at most; the box runs other projects' enclaves on the same EPC.
