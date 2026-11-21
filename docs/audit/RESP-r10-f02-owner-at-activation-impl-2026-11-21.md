# RESP-r10-F02 (impl) — IMPL-PASS at `fc6c709` (branch `r10-f02-owner-at-activation`, PR #5; head `355dcaa` adds the owner's cap confirmation in a comment and the REQ text only)

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to the implementation sent at
`fc6c709`. Transcribed verbatim by the dev; this header is the only addition. The second part concerns the PR #4
merge-before-green slip and recommends branch protection with required status checks — a repository setting, the
owner's decision, raised with the owner the same day.**

---

## REQ-r10-F02 — IMPL-PASS @fc6c709 (firsthand)

The fix is exactly the ruling, and I verified it doesn't introduce a new problem:
- **state.rs** — both apply_arm and apply_anchor now `clone()` + `activate_pending()` first, then `!msg.verify(&s.owner_pk)` (the apply_message shape), and anchor_identity reads `s`. I checked the one thing that could have gone wrong: activate_pending runs on the discarded clone, so a message that then fails the sig check never persists the activation — identical safety to apply_message, no new unauthenticated-activation path. Reachability ✓ (the test drives the boundary), retirement ✓ (the old pre-activation `!msg.verify(&self.owner_pk)` is deleted, not left as a dead path).
- **mandate.rs** — `timelock_blocks == 0 || > MAX_TIMELOCK_BLOCKS` (52_560), honest "owner's design call" comment. ✓

**The vectors break-test both directions, for Arm AND Anchor, and they are non-hollow** — I read them:
- control (no rotation) ok; before activation → old accepted, new POLICY_SIG; at activation → new accepted WITH the rotation activating (owner_pk flips to witness, pending_owner gone, nonce 2) and the retired key POLICY_SIG, with the assertion "the retired key must not re-root the anchor" naming exactly the Anchor concern; apply_message Cancel by the new owner agrees.
- hollow-f01.sh case 9 (revert verify to `self.`) ⇒ RED, case 10 (drop the cap) ⇒ RED. That's the mutation proof the two new guards bite. 10/10 holds.

No wire change; the reproducer moved to regressions. Merge is gated on this IMPL-PASS, which you have — but the MRENCLAVE bump, the ceremony build (O01 + F02), migration and deploy stay the owner's; this is a fix authorization at ref fc6c709, not a go.

## PR #4 merge-before-green — noted, low harm here, but tighten the mechanism
Thanks for the honest account. No security impact this time: the merged content is 14e1965 (harness-only, `ci` + fuzz-replay green) + docs, and fuzz-smoke on a harness PR is a quality signal, not a production gate. So I'm not worried about b7f7505's contents.

But the slip is worth closing properly, because the same watcher on a PRODUCTION-code PR would merge a regression before CI spoke. The durable fix isn't a smarter watcher — it's **branch protection on main requiring the status checks (ci, fuzz-smoke, fuzz-replay) to be green on the exact head**, so GitHub itself refuses a premature merge and a re-push that resets the checks re-blocks it. A watcher that merges on "first check registered" will always have this race. Please confirm b7f7505's `ci` (44923765072) and fuzz-smoke (44923765031) land green and forward them — and if you add the branch-protection rule, that closes the class, not just this instance.

Good, clean implementation — the Anchor-re-root assertion in particular is exactly the property I was worried about.
