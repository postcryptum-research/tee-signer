# RESP — R7 DESIGN: no signature after a restart until the owner arms the enclave — DESIGN-PASS (CONDITIONAL)

**Date:** 2026-11-05 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r7-arm-after-restart-design-2026-11-05.md`.
Recorded verbatim by the dev session. (The §2.6 build-time opt-out, question 5, was sent after
this verdict and is answered separately when it arrives.)

---

DESIGN verdict: CONDITIONAL PASS. The core is sound — rollback ⟹ restart ⟹ a fresh in-enclave challenge ⟹ unarmed, and arming needs a fresh owner signature over THIS boot's challenge that root can neither forge nor replay (old Arm carries an old challenge → ARM_CHALLENGE). It reduces §1 from "unbounded float, silent, no owner action" to "one window's budget per arm the owner approves over an unnoticed rollback, attended and visible." That meets the owner's "compose, send, sleep" by making the asleep path hard-refuse-until-armed, with the human only in the arm loop (where it was always going to be). Conditions below are must-holds, not nice-to-haves.

THE ONE I'll put first — you already have a sealed `armed`. state.rs has `s.armed` (set false by the witness disarm at judge.rs:170, true by Rearm at :459) and State is the sealed struct, so s.armed ROLLS BACK. REQ-r7's boot-arm must be a SEPARATE, volatile flag, and the SIGN gate must check the VOLATILE one, never s.armed. If the two get conflated — if boot-arm is ever sealed, or SIGN gates on s.armed — a blob sealed-while-armed loads armed and the whole scheme is void. Spell out in §5 that SIGN requires (volatile boot-arm) AND whatever s.armed still governs, and that they are distinct fields.

Must-hold conditions:
1. boot_challenge drawn by IN-ENCLAVE RDRAND / sgx_read_rand, never an OCALL to the host RNG. If the host sources it, root returns a prior value and replays an old Arm. This is the hinge of the whole design — state it as a hard requirement and I'll check it at impl.
2. The volatile boot-arm is never sealed and is reset to false on every process load (so rollback ⟹ restart ⟹ unarmed holds universally).
3. Sealed state is loaded ONCE per process; no mid-process "reload"/re-open path may keep arm=true over a swapped blob. If any such path exists it must force arm=false. (Your "every rollback is a restart" is true only while this holds — confirm there's no in-process re-read of the sealed file.)
4. COMPLETENESS, same discipline as the control-coin review: EVERY signing entrypoint checks the volatile boot-arm. Enumerate them — payout, CPFP/fee-bump, consolidation, sweep, recovery spend. One ungated signer is a full bypass. This is the blocking check at IMPL-PASS.
5. seq_seen integrity: wallet.json / the owner's last_seen_seq MUST live in the owner's trust domain (the laptop with the YubiKey), not on the server. The enclave's seq_seen ≤ s.seq check only catches a rollback when the owner reports a seq HIGHER than the rolled-back enclave; if wallet.json sits on the box, root rolls it back too and feeds a matching-low seq_seen, and the check passes silently. With wallet.json in the owner domain the residual is narrow (owner must be socially-engineered into arming a rollback); on the box it's wide. Make the location a requirement.

Your four questions:

(1) Attended override vs hard refusal on seq regression — KEEP the override, but loud. A hard refusal bricks legitimate recovery (restore-from-backup after disk loss; a crash between the enclave's seq-advance and the wallet.json write), so you need it for liveness. But it is the one door the drain re-enters, so: show the exact regression as what it is ("the enclave remembers N fewer operations than you last saw — this is the signature of a state rollback"), require a distinct explicit confirmation (never a default-yes), log it as an owner-attested acceptance of a rollback, and treat frequent firing as an incident, not a habit to click through. It does NOT violate the owner's no-human-asleep rule: arming is attended by design; the asleep path stays hard-refused.

(2) Accept other owner messages while unarmed — YES, accept, your reasoning is right. SIGN is the only value-extracting path; cancel/tighten/freeze/rotate/recover are owner-authenticated and either non-value or timelocked, and freeze is safe-direction, so the owner must keep emergency control without first doing the arm dance. Two checks: a loosening or rotate accepted while unarmed must still sit behind its timelock (no acceleration), and a freeze taken while unarmed must persist into the armed state.

(3) Pure-core shape — the shape is right: draw the challenge in rcore, pass it into the pure core as data (SessionView{boot_challenge}), keep arm as a volatile value in rcore/session.rs, core stays a pure function of (sealed state, msg, session view). I'm reasoning about core purity in general here — map it to rule 8's exact wording yourself — but the data-in / volatile-flag / pure-core separation is correct, PROVIDED the volatile boot-arm is the distinct field from point-first above, not s.armed.

(4) Any sig from a freshly loaded rolled-back state without an Arm over this boot's challenge — NO, subject to conditions 1–4. Fresh load is unarmed; SIGN refuses NOT_ARMED; arm=true is set only by a valid Arm (owner sig + matching fresh challenge + nonce + seq_seen ≤ s.seq); the attacker can't forge the sig, and an old Arm fails the challenge match; RDRAND collision is ~2^-256 and uncontrollable by root IF it's in-enclave (condition 1). The residual paths are exactly conditions 1–4: host-sourced challenge, a sealed/again-s.armed arm, a mid-process reload, or an ungated signer. Close those and there is no path.

Net: simpler than the control coin (one message, one volatile value, no per-tx overhead, no payout serialization) at a liveness cost (payouts pause until the owner arms after each restart) and the stated residual — the owner's call, and a fair one. CONDITIONAL PASS on conditions 1–5 + the distinct-from-s.armed point. Keep the control coin on record as the zero-liveness-cost alternative as you've done. When it's coded I'll IMPL-PASS with the completeness enumeration (condition 4) and the RDRAND source (condition 1) as the blocking checks.

---

**Dev's reading:** DESIGN-PASS with conditions C-R7-1 … C-R7-6 (`CONDITIONS.md`); implementation
may start on a branch; IMPL-PASS gates on C-R7-1 (in-enclave RDRAND) and C-R7-4 (completeness).
