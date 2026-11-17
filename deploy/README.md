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

## T1 box reboot checklist (firmware window 2026-11; re-verified read-only 2026-11-11)

**What persists (nothing of ours is volatile):** `~/tee-signer/` (sources, rsync of the laptop tree),
`~/tee-signer-out/` (build evidence), `~/tee-signer-btcpay/` (btcpayserver-docker clone, `Generated/`
compose, `plugin/` DLL + `plugin-new/`, `e2e/{apikey,store}`), `~/tee-signer-state/` (the stopped host
signerd of R2 and the sidecar token copy the e2e uses), `~/tee-signer-keys/enclave-dev-2.28.pem`,
`~/btcpay-tee-lab/`, and the seven docker volumes `tee-btcpay_{bitcoin_datadir, bitcoin_wallet_datadir,
btcpay_datadir, btcpay_pluginsdir, nbxplorer_datadir, postgres_datadir, tee_signer_datadir}` (the
sidecar's sealed state, receipts and token live in the last one). `/tmp` is cleaned at boot (tmpfiles
`D /tmp`); **none of our files are there** — `/tmp/claude-1000/` holds other projects' scratch only.
Plugin settings and the store's API key are in BTCPay's Postgres volume. Nothing needs a backup for a
reboot; the dev wallet (fp `8c3ce9a6`, signet) is recoverable from the laptop's record anyway.

**What starts by itself:** `docker` and `aesmd` are `systemctl enabled`; the five containers
(`btcpayserver_bitcoind`, `generated_postgres_1`, `generated_nbxplorer_1`, `generated_btcpayserver_1`,
`tee-btcpay-tee-signer-1`) are `restart: unless-stopped`. The sidecar needs `/dev/isgx` **and** the
`/var/run/aesmd` socket; if it comes up before `aesmd` it fails and docker retries it (backoff) — give it
a minute.

**The one hard dependency:** the legacy SGX driver exists only for the pinned kernel —
`/lib/modules/5.15.0-138-generic/kernel/drivers/intel/sgx/isgx.ko`; the installed `5.15.0-203-generic`
has **no** `isgx`. `GRUB_DEFAULT` is pinned to `-138`. Booting `-203` without a rebuilt `isgx` leaves the
sidecar in a restart loop (`no /dev/isgx`) — a pause of the T1 dev signer, no loss; the T2 node is not
involved. Rebuilding `isgx` for `-203` is a box-level change (sudo, shared) — the owner's/coordinator's call,
not this project's.

**After the reboot — checks, all read-only (box):**
```sh
uname -r                                   # expect 5.15.0-138-generic
ls -l /dev/isgx && lsmod | grep -c isgx    # device + module
systemctl is-active docker aesmd           # active active
docker ps --format '{{.Names}}  {{.Status}}'   # five containers Up
curl -s -o /dev/null -w '%{http_code}
' -H "Authorization: Bearer $(cat ~/tee-signer-state/token)" http://127.0.0.1:7390/v1/status   # 200
curl -s -o /dev/null -w '%{http_code}
' http://127.0.0.1:7392/     # 302 (BTCPay login redirect)
```
The T1 sidecar runs the R6 build: no R7 pause, **no `arm` needed** after the restart.

**After the reboot — by hand (dev, from the laptop):**
1. The box→Azure owner forward dies with the reboot; recreate it on the box:
   `ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:7395:127.0.0.1:7390 azureuser@52.236.130.102`
2. The laptop's master tunnel to the box drops; re-open it and its forwards:
   `ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -M -S .local/signet/tunnel.sock -f -N -L 7390:127.0.0.1:7390 andrey@94.130.18.162`,
   then `ssh -S .local/signet/tunnel.sock -O forward -L 7395:127.0.0.1:7395 andrey@94.130.18.162`.
3. The 7398 forward targets our compose `btcpayserver_bitcoind` by container IP (today `172.18.0.3:43782`);
   docker may hand it another IP after the reboot — read it (`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' btcpayserver_bitcoind`)
   and forward `7398:<ip>:43782`; the RPC cookie is regenerated by bitcoind at start — re-copy it:
   `docker exec btcpayserver_bitcoind cat /data/signet/.cookie` → laptop `.local/signet/hetzner-node.cookie`.
4. If the stack did not come back: `cd ~/tee-signer-btcpay && ~/tee-signer/btcpay/docker/stack.sh up` (T1 fragment is the default); then the checks above.

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
| T2 wallet (signet, dev) | **since 2026-11-12 (ceremony-signed R9 build `c7c5d8ef…`, no TPM yet → behaves as R7):** xpub `tpubDDUrStb…ET4o`, fingerprint `cc685457`, enclave id `9f79215d…`, MRENCLAVE `c7c5d8ef373b57083034693616b06b2dc0f12b345ee905b8b0d8be8d4f527db0`, MRSIGNER `56b25ccb…` (ceremony key), mandate `67c35535…` (same caps as R7: unlisted 100 000/tx, 500 000/window; window 144 blocks, 2 000 000 outflow), owner `piv:9a@39252737`, recovery key the owner's `recovery-r7.key` (same key as before); image on the node `tee-signer/signerd:t2` = `c933b91baeff` (the same tarball as the box's `86214e0e7dc5`, sha256 `f256bc31…`), armed load `87129c5b…`, nonce 1, seq 0; record + logs in the laptop's `.local/signet-t2/` (gitignored). **Retired the same day:** the R7 wallet `51ca22a4` / `ca5c1a6a…` — state in the volume's `retired-ca5c1a6a-2026-11-12/`, record `wallet-ca5c1a6a-retired-2026-11-12.json`, **67 337 signet-sat still in it** (recoverable from the archived record's blob with the recovery key). Earlier: the R6 wallet `fae69580` / `51dee44d…` (`retired-51dee44d-2026-11-10/`) |

## R8 — no tunnel: the owner's files

Owner operations never cross a tunnel. The sidecar mounts an exchange directory
(`TEE_EXCHANGE_DIR`, default `~/tee-signer-exchange` of the user who runs the stack, seen as
`/exchange` inside the container; create it `-m 1777` — the sidecar writes there as uid 999). The owner's machine sends files there with `scp` (public keys,
a nonce, signed messages) and takes files back the same way (`init-response.json`, `status.json`,
`quote.json`, `policy.json`, `*.result.json`). On the server the steps are
`docker exec tee-btcpay-tee-signer-1 signerd status|submit|init|quote|policy|freeze --state-dir /var/lib/signerd … --out /exchange/<file>`;
each writes its answer as a file and exits 0 on `ok`, 1 on a refusal (the enclave's reasons are in
the file). `ssh` is never used to pull a process's output; `docs/FAQ.md` setup 1 is the worked
sequence. The dev tunnels of earlier rounds (7390/7395/7398 forwards) remain a developer
convenience, not an operator path.

The 2026-11-10 T2 redeploy (C-R7-13) is the worked, owner-run example of this scheme end to end:
`scripts/t2-r7-redeploy.sh` — run on the laptop in the owner's own terminal (prompts: recovery
passphrase once, YubiKey PIN + touch twice); it stops the sidecar, sets the previous wallet's state
aside in the volume, starts the new image, `init`/`quote`/`status` to files, verifies the quote on the
laptop, installs the mandate, runs the restart drill (`arm`) and re-points the T2 BTCPay store and
plugin. Not idempotent: a second run retires the wallet it just created.

### Dev stack operations run by hand on 2026-11-10 (so they are not lost)

| Step | Where | Command / action | What happens |
|---|---|---|---|
| browser access to the T2 BTCPay | laptop + box | on the box `ssh -f -N -L 127.0.0.1:7397:127.0.0.1:7392 azureuser@52.236.130.102`; on the laptop `ssh -S .local/signet/tunnel.sock -O forward -L 127.0.0.1:7397:127.0.0.1:7397 andrey@94.130.18.162`; open `http://127.0.0.1:7397` (login `admin@tee.local`, dev password in `btcpay/e2e/gates.sh`) | two ssh forwards chained through the box; BTCPay itself stays bound to loopback on the node. Remove with `-O cancel` on the laptop and `kill` of the box-side ssh (parking) |
| wallet rescan after importing an xpub that already received coins | BTCPay UI | store → Wallets → BTC → `…` → **Rescan** | NBXplorer indexes only from the moment it starts tracking a derivation; coins that arrived before (or while it was not yet tracking) are found by the rescan. The enclave is not involved |
| restart BTCPay only | node | `docker restart generated_btcpayserver_1` | BTCPay restarts (~30 s); the sidecar keeps running, so the enclave does **not** pause and no `arm` is needed |
| build the plugin | box | `cd ~/tee-signer/btcpay && DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile.plugin-build --target export -o ~/tee-signer-btcpay/plugin-new .` | a `dotnet/sdk` container clones BTCPay v2.4.7 and publishes the DLL into `~/tee-signer-btcpay/plugin-new/` (~2 min) |
| upgrade the plugin on a stack | box → node, node | `scp ~/tee-signer-btcpay/plugin-new/BTCPayServer.Plugins.TeeSigner.dll azureuser@52.236.130.102:tee-signer-btcpay/plugin/` then on the node `~/tee-signer/btcpay/docker/stack.sh install-plugin` (T1: the same `install-plugin` on the box) | the DLL is copied into the BTCPay container's `Plugins/` directory and BTCPay restarts; keep the previous DLL next to it as `*.before-<date>` to roll back. The enclave is untouched |
| delete the R4 seed-leak test wallet from the T1 compose bitcoind (owner's yes 2026-11-11) | box | `docker exec btcpayserver_bitcoind bitcoin-cli -datadir=/data -signet unloadwallet t2-seed-leak` then `docker exec btcpayserver_bitcoind sh -c 'rm -rf /walletdata/signet/t2-seed-leak'`; verify `listwalletdir` → `[]` | the bitcoind wallet created on 2026-11-03 for the seed-leak vector held the private keys of the burned T2 wallet (fp `fae69580`, 22 153 signet-sat of test change); a vector artefact must not outlive the vector — found during the firmware-window backup inventory. The seed of that wallet stays recoverable from the laptop's archived record |
| enable the vTPM on the Azure VMs (R9 product path, option A of [issue #1](https://github.com/77ph/BTCPayTEE/issues/1)) — procedure agreed 2026-11-17 | the operator's Azure account (a colleague converts the VMs one by one; every project brings its own services back; the dev joins once `sgx-node-3` is back) | `scripts/azure-enable-vtpm.sh <vm> [--check-only] [--ssh azureuser@<ip>]`, one VM per run, Enter between steps, log in the cwd: step 0 shows the subscription and the VM; step 1 is read-only (not already Trusted Launch, size without `TrustedLaunchDisabled`, OS disk Hyper-V gen V2, every public IP Static, no Azure Backup — in this subscription `Microsoft.RecoveryServices` is not even registered, so neither Backup nor Site Recovery can exist); step 2 `az snapshot create` of the OS disk; step 3 `az vm deallocate`; step 4 `az vm update --security-type TrustedLaunch --enable-vtpm true --enable-secure-boot false` (a refusal changes nothing: the script starts the VM again and exits); step 5 `az vm start`; step 6 inside the guest `ls -l /dev/tpm0 /dev/tpmrm0`, `cat /sys/class/tpm/tpm0/tpm_version_major`, the SGX devices, `docker ps`. Checked 2026-11-17 read-only on all three VMs (`sgx-node-1/2/3`: `Standard_DC2s_v3`, `22_04-lts-gen2`, Standard, static IPs, no Backup): `--check-only` passes. After `sgx-node-3` (auditor's question 2026-11-17, answered from the code): the conversion re-places the VM, and the sealed state is bound to the CPU (`sgx_seal_data_ex(KEYPOLICY_MRENCLAVE)`), so on a different host the live wallet `cc685457` answers `STATE_UNSEALABLE` — seed, identity key, mandate and counter binding are gone with it, the disk is intact, there is no seed-import op in the release build (CONTINUITY §1). Expected path: the dev checks the devices and `signerd status`; the owner installs `tpm2-tools`, records in the issue what `tpm2_getcap handles-nv-index` shows and the issuer of whatever certificate the vTPM carries (`tpm2_nvread -C o 0x01c00002` for an EK; on an Azure Trusted Launch vTPM reportedly none — Azure's AK certificate at `0x01c101d0` instead; piped to `openssl x509 -inform DER -noout -issuer -subject -dates`) — a *record*, not a binding: it does not prove our AK lives in that TPM (THREAT-MODEL §5 "TPM identity at anchor time"), leaves the old wallet's 42 566 signet-sat where they are — owner's decision 2026-11-17 (relayed by the auditor, after the readiness report): **abandon**, no sweep tool now; the decrypt half of the recovery (D1 on the live blob, 2026-11-12) stays proven, the sweep path (`tools/recovery-sweep`, auditor's seed-hygiene checklist: words from stdin only, never persisted or logged, local signing, one sweep tx) is validated later, when mainnet is actually near; `recovery-r7.key` confirmed backed up on a second medium — then a **new wallet on the same MRENCLAVE** (no new ceremony) per the 11-12 worked example with `tpm-setup --no-orderly` done **before** its `init` and the TPM overlay from the first `up`, then `anchor` — the next row, reordered. If the VM happens to land on the same CPU, `status` shows a normal R7 pause instead and the plain additive order applies | a VM property change: disks kept, no price change, 10–20 min downtime for every project on the VM, once per VM; our containers are `unless-stopped` and come back alone; the sidecar then shows either the R7 pause (same CPU) or `STATE_UNSEALABLE` (different host — the expected case) — both expected, neither a failure; Secure Boot stays off on purpose; roll-back to Standard is one-way, the snapshot is the way back if a VM does not boot; the EK issuer seen on the node is what the owner later checks on the laptop before `anchor` |
| test the `tss` TPM transport against the laptop's own TPM (R9, no tunnel, no node) | laptop | `(cd host/signerd && cargo build --features nosgx,tss)`, then `E2E_DIR=<scratch> scripts/e2e-tss-local.sh` (handles `TSS_AK=0x81000200`, `TSS_NV=0x01800200` by default — the script refuses to start if either is occupied, and never evicts) | `signerd tpm-setup` creates a restricted P-256 attestation key and a counter index at the two handles (refusals for the owner's key `0x81000100` and the EK certificate index `0x01c00002` are exercised first and create nothing); a nosgx daemon runs with `SIGNERD_TPM=tss:device:/dev/tpmrm0?ak=…&nv=…`; the owner anchors from a real `TPM2_NV_Certify`; the counter follows the seals; an unattended restart auto-arms; a rolled-back state is `STATE_STALE`; `tpm-teardown --setup-file tpm-setup.json` removes the two objects only after their key and Name match the record (a foreign key, a wrong record and a missing record are each refused first), and the script diffs `tpm2_getcap handles-persistent` / `handles-nv-index` against the snapshot taken before — they must be identical. The laptop's other handles (`0x81000001/2/9`, `0x81000100` = the owner key, `0x81010010/12`, `0x81800000/1`; NV `0x141000x`, `0x1820002`, `0x188000x/11`, `0x1C00xxx`) are other projects' or the firmware's — never touched |
| put the vTPM in front of the T2 signer once issue #1 is done (R9 product path) — **2026-11-17: because the conversion re-places the VM, the live state is expected to be `STATE_UNSEALABLE` afterwards; the order becomes step 2 → step 3 as a NEW wallet on the same MRENCLAVE (the 11-12 worked example, no new ceremony; old coins via the recovery blob) with the TPM overlay from its first `up` → step 4** | box, node, laptop | **1. build (box):** the pinned build image carries `libtss2-dev` and builds the daemon with `--features sgx,tss` (since 2026-11-11; gate 5 that day: the same sources under the old and the new image give a byte-identical `enclave.so`, MRENCLAVE `c7c5d8ef…` — outputs kept in `~/tee-signer-out/r9-main-baseline` and `~/tee-signer-out/r9-tss`, image `tee-signer-build:2.28-tss` kept as the build cache); the enclave of current `main` is a **new MRENCLAVE** — the live `ca5c1a6a…` predates R9, and the counter check lives in the enclave — so it is signed by the **ceremony** again: `SIGN=ceremony PHASE=gendata OUT=~/tee-signer-out/r9-ceremony docker/build-enclave.sh` → `scripts/ceremony-sign.sh` on the owner's machine → `PHASE=catsig` → `btcpay/docker/build-signerd-image-t2.sh ~/tee-signer-out/r9-ceremony` → the tarball to the node (`docker load`). **2. node, once:** `sudo apt-get install -y tpm2-tools`, `tpm2_getcap handles-persistent; tpm2_getcap handles-nv-index` (pick two free handles), then the one-shot setup on the new image **before** the sidecar runs with the TPM: `docker run --rm --device /dev/tpmrm0 --group-add $(getent group tss \| cut -d: -f3) -e SIGNERD_TPM_AUTH="$TEE_TPM_AUTH" -v ~/tee-signer-exchange:/exchange --entrypoint /usr/local/bin/signerd tee-signer/signerd:t2 tpm-setup --ak-handle 0x81000200 --nv-index 0x01800200 --no-orderly --out /exchange/tpm-setup.json` (`--no-orderly`: a vTPM has no flash to spare and a hard reset must not look like a rollback; keep `tpm-setup.json`, teardown needs it). **3. stack:** a new MRENCLAVE is a **new wallet** (FAQ "How do I move to a new enclave build": empty the old one, retire its state, `init`/`quote`/verify against the new MRENCLAVE, mandate, re-import the xpub, new token for the plugin — `scripts/t2-r7-redeploy.sh` is the worked example); bring it up with the TPM overlay: `TEE_FRAGMENT=opt-add-tee-signer-t2.custom TEE_EXTRA_FRAGMENTS="opt-save-storage-xxs;opt-add-tee-signer-tpm.custom" TEE_TPM_GID=$(getent group tss \| cut -d: -f3) TEE_TPM_AUTH=<the same secret> ~/tee-signer/btcpay/docker/stack.sh gen` then `up` (the fragment maps `/dev/tpmrm0`, adds the gid, sets `SIGNERD_TPM` and `SIGNERD_TPM_AUTH`; `TEE_TPM_SPEC` overrides the handles). **4. owner:** `signerd tpm-info --out /exchange/tpm-info.json` on the node, carry it; `openssl rand -hex 32 > nonce.txt`, carry it to the node; `signerd tpm-certify --nonce-file … --out /exchange/anchor-proof.json`, carry it back; `owner-cli --status-file … --wallet-record … --out anchor.msg anchor --key piv:9a --tpm-info-file tpm-info.json --proof-file anchor-proof.json --proof-nonce-file nonce.txt`; `signerd submit --file /exchange/anchor.msg` on the node (the file-exchange form is exercised by `scripts/e2e-tss-local.sh`) | the attestation key and the counter live in the hypervisor's vTPM; every state change and signature carries a `TPM2_NV_Certify` over the enclave's nonce and the state expects the counter one higher after each seal; a restart arms itself when the counter agrees (no `arm` ceremony); a rolled-back or desynchronised state is `STATE_STALE` until the owner re-anchors with step 4. The old wallet's record (recovery blob) is kept next to the new one. `tpm-teardown` is **never** run on the node while a state is anchored to the objects |
| add hints to the existing owner secrets (owner's ask 2026-11-12; optional, any time) | laptop | `owner/owner-cli/target/debug/owner-cli key-hint --key .local/signet-t2/recovery-r7.key --set "<where the passphrase is kept>"` (asks the passphrase once); `scripts/ceremony-key-hint.sh --set "<where the passphrase is kept>"` (asks the passphrase once, same checks, verifies the pinned public key is unchanged); `owner-cli --wallet-record .local/signet-t2/wallet.json key-hint --pin --set "<where the PIN is kept>"` | the hint is stored next to the secret (keyfile JSON field `hint`, a text line before the PEM block, `owner_pin_hint` in the wallet record) and printed before the corresponding prompt; ciphertext and public keys are untouched (the keyfile rewrite re-reads and compares them). Never write what the passphrase is or looks like — FAQ "I forget passphrases" |
| **migrate T2 to the ceremony-signed R9 build `c7c5d8ef…` — DONE 2026-11-12 (owner-run)** | laptop (owner's terminal), node | What ran: `docker load` on the node (dev); the owner's `t2-r9-redeploy.sh` (= the 11-10 worked example with this build's values; copy in `.local/signet-t2/`) did step 1 on the node (sidecar stopped, R7 state → `retired-ca5c1a6a-2026-11-12/`, start on the new image, token rotated, `init`, quote, status) and then **stopped at the laptop's verifier step 6** — not an attack: the script never sends `nonce.txt` (nor `owner.pub`, `recovery.pub`) to the node, so the node quoted over the 11-10 nonce still lying there while the laptop checked the fresh one. The auditor's gate for continuing instead of wiping: a fresh quote over a **brand-new** nonce must pass all 7 steps (it did), and the failure's mechanism must be shown (a quote over the recovered 11-10 nonce verifies against it). The resume (`t2-r9-redeploy-resume.sh`, the same script from step 2 with a guard that the quote carries our nonce) then did: record written (`wallet-c7c5d8ef.json` → `wallet.json`, old record archived), `recovery-verify` OK, mandate `67c35535…` installed at nonce 0, restart drill `boot_armed false` + challenge `f59ce9cd…` → owner `arm` → `boot_armed true`, nonce 1 (the R7 deployment facet on the new measurement), store wallet = new xpub, plugin = new token (`xpubMatches true`). **Lessons for the next run of the worked example:** (1) send `nonce.txt owner.pub recovery.pub` to the node's exchange dir **before** step 1 (`to_node`), and generate the nonce fresh each time; (2) never reuse a filename for a security artefact under investigation — the failed quote's bytes were lost to a same-name re-quote; keep `quote-<stamp>-<nonce8>.json`; (3) the script's retired-dir name is per day: a second run the same day would `mv` the fresh state over the retired one — never re-run it as is | new wallet, new seed, new token; the old wallet's coins stay recoverable; without a TPM the R9 enclave is R7 (unanchored, owner arms after restarts); the vTPM step later is `tpm-setup` + the compose overlay + `anchor` on this very state — **only if the VM keeps its CPU**; the vTPM conversion re-places it, so expect `STATE_UNSEALABLE` and a new wallet (CONTINUITY §1, row above) |

