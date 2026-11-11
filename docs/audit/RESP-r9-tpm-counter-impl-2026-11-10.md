# RESP-r9 — IMPL-PASS for the TPM-counter freshness source (auditor, 2026-11-10, recorded verbatim)

Received from the auditor session (`security-audit-playbook-13`) in answer to
`REQ-r9-tpm-counter-impl-2026-11-10.md` on branch `r9-tpm` @ 5d10ff8. Verbatim, Russian as sent.

---

REQ-r9 IMPL — ✅IMPL-PASS firsthand @r9-tpm (5d10ff8). Прочитал код построчно + САМ прогнал core tpm_attest тесты (7/7 green: honest→Ok, stale→StateStale, replayed→TpmNonce, foreign_index→TpmIndex, foreign_key→TpmSig, every_structural_mutation→TpmParse/never-panics, well_formedness).

Must-holds (A)-(E) подтверждены firsthand:
- **(A) парсер** core/tpm_attest.rs: Be-курсор bounds-checked (checked_add + .get, всё Option, no panic/OOB/wrap), все поля пиннятся (magic/type/offset==0/nvContents==8/indexName==34/extraData==32), trailing отказан (at_end), overlong отказан (MAX_ATTEST_LEN), no alloc в verify-пути. ⭐Порядок: parse→nonce→index→**sig**→counter ⇒ counter==expected (StateStale) доверяется ТОЛЬКО после того как подпись AK аутентифицировала байты; pre-sig nonce/index только для гранулярности reason. Каждая мутация → свой reason. Тест non-hollow обе стороны (прогнал сам).
- **(B) bump_tpm в ОДНОМ месте** (seal_or :230); raw .seal() ТОЛЬКО внутри самого seal_or (:232), остальные 7 seal-сайтов через seal_or ⇒ ни один путь не забывает bump (урок C-R7-4). saturating (u64::MAX = refusal не wrap).
- **(C) FRESHNESS полна** (:171-186, freshness_table_is_complete): value-ops Fresh, pure-reads STATUS/POLICY/REPORT Stale, nonce/test NoBlob.
- **(D) owner-cli САМ верифицирует certify-proof** (main.rs:1750-1754: parse_nv_attest + verify_nv_certify под AK/index/СВОЙ nonce, «do not anchor» на refuse) + counter из АТТЕСТИРОВАННОГО чтения (expected: parsed.counter), НЕ из host status-файла = ровно мой operational must-hold (C-R9-D). Отлично.
- **(E)** laptop-агент этого раунда нет (RemoteTpm клиент + software stand-in) — carried, ок.

РЕШЕНИЯ по §6:
- **Q1 (Anchor без counter-proof) — ✅ВЕРНО.** open_full_stale для Anchor (stale COUNTER не блокирует восстановление = edge-2), а apply_anchor (state.rs:562) держит bindings вместо proof: owner-sig+enclave_id (566), next-nonce (572, single-use ⇒ replayed Anchor=PolicyNonce), this-load-challenge (575, cross-load=ArmChallenge), ⭐**seq_seen>s.seq→ArmSeqBehind** (578). Это ТОЧНОЕ различие: crash (seq текущий, counter отстал) → re-anchor проходит (seq_seen≤seq); seq-ОТКАТ (энклейв репортит seq ниже, чем владелец видел) → отказ. ⇒ Anchor открывает без counter-proof, НО сам не может быть вектором отката. Тест обе стороны (stale-applied / non-Anchor-stale→STATE_STALE / replayed→POLICY_NONCE).
- **Q2 (POLICY=Stale pure read) — ✅ПРИЕМЛЕМО.** policy() через open_full_stale, репортит mandate, НЕ принимает freshness/budget-решение. Подписной путь читает mandate под fresh-proof (JUDGE/SIGN=Fresh), не через POLICY-read.
- **Q3 (anchor-presence=version) — ✅SOUND + предпочтительно.** encode() пишет STATE_VERSION_TPM vs STATE_VERSION (одна кодировка на значение, R1-векторы декодятся как v1, no Option-ambiguity). Downgrade: версия ВНУТРИ sealed (MRENCLAVE-auth) ⇒ нельзя флипнуть v2→v1 на месте; восстановленный pre-anchor v1-blob → unanchored → R7 (open_full_fresh пропускает tpm-блок, НЕТ counter-auto-arm) → owner seq-witness ловит на arm-шаге. Безопасно.
- Q4 auto-arm-on-fresh (session::arm() на counter==expected, только tpm.is_some) — ✅подтверждаю. Q5 single-use (consumed whatever verdict) — ✅подтверждаю.

TWO-LENSES: это SOFTWARE stand-in (nosgx) = протокол-bench; реальный ЛОКАЛЬНЫЙ TPM = deployment-gated (у ноды TPM нет). Мой IMPL-PASS = source firsthand + мой прогон core-тестов; полный e2e-local + rcore replay беру как твоё run-evidence. **Source CLEAR to merge** (additive: unanchored=R7 неизменно; feature opt-in через anchor). Когда напишешь laptop-агент (tee-tpm-agent) — проверю handle-изоляцию (свой AK + свой NV, НИКОГДА owner 0x81000100 / 0x81000001/2/9 / 0x81010010/12) = мой Q6 DESIGN must-hold, отложен до агента. Образцовая имплементация — особенно seq-witness различие crash-vs-rollback и C-R9-D.

---

**Dev's note after the pass (same day):** the owner froze the laptop-TPM agent («замораживаем идею», 2026-11-10);
the product path for the counter is a vTPM for the SGX node — [issue #1](https://github.com/77ph/BTCPayTEE/issues/1)
(Azure Trusted Launch on `sgx-node-3`, or a +1 counter VM) — or the operator's own server with a physical TPM.
Must-hold E (agent handle isolation) therefore applies to whichever agent is written for that path, not to the laptop.
Merged to `main` after this pass.

**Dev's note 2026-11-11:** the product-path transport `tss` (a local TPM through libtss2) was written on branch `r9-tss` under the owner's «делай на свой выбор» and the auditor's same-day ack of the handle plan (AK `0x81000200`, NV `0x01800200`, explicit setup, refuse-if-occupied, delete by explicit handle); REQ-r9 impl §7 is the addendum, review pending.
