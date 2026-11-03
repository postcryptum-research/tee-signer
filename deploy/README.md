# DEPLOY — isolation plan (shared SGX host)

Build/dev host: `94.130.18.162` (`aatproject`, Hetzner). Shared with the perp DEX, Phoenix,
trust-bridge, ethsigner, rippled, two `bitcoind`s (regtest 18443-18445, testnet4 48332-48334),
PostgreSQL 5432, nginx 80/443. **Survey 2026-11-03, read-only.** Nothing of theirs is touched.

## Host facts (measured 2026-11-03)

| Fact | Value |
|---|---|
| CPU | Xeon E3-1275 v6; **SGX1 only, no FLC**, legacy `/dev/isgx` 2.11; EPC ≈ 94 MiB shared |
| SDK / PSW | `/opt/intel/sgxsdk`, PSW 2.25 (`aesmd` active); gcc 11.4, no clang |
| Launch | **debug only** on this box: a non-debug launch needs a launch token from Intel's Launch Enclave (non-FLC), issued only for Intel-whitelisted MRSIGNERs — measured: `RELEASE=1` enclave launches with neither debug=0 (0x4004) nor debug=1 (0x2004). Building `RELEASE=1` works (all gates pass). |
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

## T2 target — Azure DCsv3 `sgx-node-3` (owner's decision 2026-11-03, no cluster)

| | |
|---|---|
| node | `sgx-node-3` = `52.236.130.102`, `ssh azureuser@…` with `~/.ssh/id_rsa` **on the Hetzner box** (the laptop's key does not work; chain the tunnels through the box) |
| hardware | Xeon Platinum 8370C (Ice Lake-SP), `sgx_lc`, in-kernel `/dev/sgx_enclave` + `/dev/sgx_provision`, Ubuntu 22.04.5, kernel 6.8-azure, 2 vCPU, 15 GB RAM, 29 GB disk |
| PSW / DCAP | 2.28.100.1-jammy1 / 1.25.100.1-jammy1, `aesmd` active (ecdsa/pce/quote-ex plugins), `az-dcap-client` 1.13.0 — the build image pins exactly these |
| ours | `~/tee-signer/` (sources for the stack only — **the enclave is never built on the node**), `~/tee-signer-btcpay/` (btcpayserver-docker + Generated), Docker 29.1.3 (installed 2026-11-03 with the owner's approval, `azureuser` in `docker`), loopback ports **7390** signerd, **7392** BTCPay; occupied by others: 22 53 3000 4002 5432 7195 7777 8086 9089 9191 9199–9202 |
| not ours | trust-bridge seats `c2/c5/c8/c12`, perp, phoenix, Postgres 5432 — never touched, same rules as the Hetzner box |
| build | on the Hetzner box: `docker/build-enclave.sh` (pinned image `tee-signer-build:2.28`, outputs in `~/tee-signer-out/<name>/`), `docker/compare-builds.sh a b` (gate 5), `btcpay/docker/build-signerd-image-t2.sh <out>` → `signerd-t2-image.tar.gz` shipped to the node with `docker load` |
| stack on the node | `TEE_FRAGMENT=opt-add-tee-signer-t2.custom ~/tee-signer/btcpay/docker/stack.sh gen|up|…` — same shape as the dev stack, sidecar on the in-kernel driver with `SGX_AESM_ADDR=1`, `SIGNERD_ENCLAVE_DEBUG=false` |
| signing key | `~/tee-signer-keys/enclave-dev-2.28.pem` on the Hetzner box, 0600, **dev key, labeled** (a release key is a ceremony); never in an image or in git |
| node disk | **29 GB, shared with the siblings' data.** Signet IBD unpruned took it to 95 % on 2026-11-03; our `bitcoind` was stopped at once and runs **pruned** (`TEE_EXTRA_FRAGMENTS=opt-save-storage-xxs`, 5 GB). Check `df -h /` before any new data on the node |
| token / owner access | sidecar token copy at `~/tee-signer/token` on the node (0600); from the laptop: Hetzner forward `ssh -f -N -L 127.0.0.1:7395:127.0.0.1:7390 azureuser@52.236.130.102` (on the box) + laptop forward 7395 through `.local/signet/tunnel.sock`; `owner-cli --signerd http://127.0.0.1:7395 --token-file .local/signet-t2/token …` |
| T2 wallet (signet, dev) | xpub `tpubDCSDiHr…heEPV`, fingerprint `fae69580`, enclave id `f742311c…`, MRENCLAVE `51dee44d…`, MRSIGNER `73f20c7b…` (dev key), mandate `802cee97…`; record + attestations in the laptop's `.local/signet-t2/` (gitignored) |
