# Continuity model — accidents, not adversaries

`THREAT-MODEL.md` is about compromise: an adversary, what they can reach, what the enclave refuses,
what the monitor detects. This document is about **accidents**: hardware that dies, a disk that is
lost, a laptop that is stolen or wiped, a key that is forgotten. Both are risks and both are
managed, but they are not the same thing and their checks have different names: the threat model
ships **attack vectors**; this model ships **recovery drills**. (Owner's rule, 2026-11-03: never
mix the two.)

## 1. What can be lost, and what the funds depend on

| Loss | Funds | Operations | Recovery |
|---|---|---|---|
| the enclave's sealed state (disk, container volume, the server itself) | **safe** — the seed is also in the recovery blob | signing stops | restore the wallet from the recovery blob into any BIP84 wallet, **or** re-initialise a new enclave wallet and move the coins there (a planned sweep, signed by the restored wallet) |
| the whole T2 node / the SGX hardware | safe (same) | stops | same; a new enclave on new hardware is a **new** wallet (new seed): there is no way to put the old seed into a new enclave, by design |
| the recovery key (file lost or passphrase forgotten) **while the enclave lives** | safe while the enclave lives | — | rotate: `rotate-owner`/`recover` cannot change the recovery key; the honest move is to **initialise a new wallet** (new recovery blob to a new recovery key) and sweep to it under the mandate |
| the recovery key **and** the enclave | **lost** | — | none — the two-of-two this design rests on; hence the recovery key lives offline and is backed up (two media, two places) |
| the owner key (keyfile or the TPM in the laptop) | safe | mandate changes impossible; signing within the mandate continues | `recover --recovery-key …` hands the owner role to a new key, immediately (DESIGN §7) |
| the laptop (operator machine) altogether | safe if the recovery key is backed up elsewhere | owner operations stop until a new operator machine is set up | restore the recovery key from its backup, then as above; the TPM owner key died with the laptop → `recover` |
| the ceremony enclave-signing key | safe | new enclave builds cannot be signed with the pinned MRSIGNER | a new ceremony key + a new pin; the running enclave keeps working (sealing is MRENCLAVE-bound) |
| the host's receipt log | safe | the monitor alarms (`SEQ_REGRESSION`) | the enclave's state still carries `seq`; the owner acknowledges after review |

The one sentence: **the seed exists in two places — inside the enclave and in the recovery blob
encrypted to the offline recovery key — and nowhere else; lose both and the funds are gone.**

## 2. Recovery drills (what has been executed, what has not)

| Drill | Status |
|---|---|
| D1 `recovery-verify` **without printing**: the blob decrypts to a mnemonic whose BIP84 xpub and fingerprint equal the wallet record's | executed on every wallet initialised so far (T1, T2, throwaways) — the standard check before funding |
| D2 full restore: mnemonic → a different BIP84 wallet → it sees the coins → it spends | **executed once on signet (2026-11-03) in the course of a threat-model vector**, which is the wrong frame: it proved the restore works, but it was run on an online laptop and the words entered a chat. The drill proper is: offline machine, air-gapped wallet, a sweep to a new wallet, and the old wallet treated as burned afterwards |
| D3 enclave loss → new enclave wallet → sweep from the restored old wallet | not executed |
| D4 owner-key loss → `recover` with the recovery key → new owner | the message path is vectored (R1/R2); the drill on a live wallet not executed |
| D5 laptop loss → recovery key from backup | not executed; the backup discipline is the owner's |

## 3. Rules that follow

- `--print-mnemonic` is a **continuity tool**: an explicit, warned, confirmed act, on an offline
  machine, for D2 only. It is never a security test and never run on a wallet one intends to
  keep using — printing it ends that wallet's life (sweep and retire).
- The recovery key never touches the BTCPay box or the build host; it is backed up on two media.
- A recovery is followed by a **retire**: the restored seed is spent to a new enclave wallet and
  never reused.
- Drills are scheduled, not improvised; each executed drill is recorded here with a date.
