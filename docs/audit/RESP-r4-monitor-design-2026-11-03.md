# RESP — R4 design: the owner's monitor — DESIGN-PASS

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r4-monitor-design-2026-11-03.md` at `dc7b5d8`.
Recorded verbatim by the dev session.

---

ВЕРДИКТ: DESIGN-PASS для R4-monitor @dc7b5d8. No-TCB подтвердил (diff main..dc7b5d8 `-- core enclave` ПУСТ; r4=REQ-doc). Этот раунд ЗАКРЫВАЕТ (в дизайне; IMPL проверит) несомые гейты: C-R2-2 cross-restart-seq-fork, C-R3-1 receipt-authenticity+chain-obs, D-R3-4, §5a feed-stall. Начинай owner-cli monitor.

АРХИТЕКТУРА — АФФИРМИРУЮ: chain-observation PRIMARY (цепь=ground-truth, receipt=claim; SPEND_WITHOUT_RECEIPT=аларм) + НЕЗАВИСИМЫЙ источник + off-host + autonomous-safe-FREEZE. Это верный «chain-as-oracle, независимый от противника(хоста)».

Рулинги:
• D-R4-1 ✓ FREEZE-рефлекс (unsigned/tightening/автономный на ALARM; unfreeze=owner-key после человека; WARN не фризит). Это КОРРЕКТНО по no-human-as-security-link: безопасное действие (freeze) АВТОНОМНО, человек гейтит только ВОССТАНОВЛЕНИЕ (unfreeze), а не безопасность — правильное место для человека.
• D-R4-4 ✓ ПОДТВЕРЖДАЮ: same-seq+same-txid=идемпотентный re-sign (benign); same-seq+different-txid=FORK (ALARM). Верно.
• D-R4-5 ✓ witness=СОБСТВЕННЫЙ HWM монитора, НИКОГДА claim сигнера (это и prevention-assist: сигнер, откатанный ниже witness last_seen_seq, отказывает FRESHNESS_SEQ_BEHIND). Cadence=interval — условие: interval ≤ freshness-окна мандата (иначе freshness-required голодает).
• D-R4-6 ✓ owner-cli monitor run субкоманда (шарит wallet-record+key-locators; long-running; restart-safe через HWM-persist-before-verdict).
• D-R4-2/D-R4-3 ✓ с УТОЧНЕНИЕМ (C4): для VALUE источник = СОБСТВЕННЫЙ узел владельца (≥2 согласных), НЕ одиночный third-party; Esplora только signet/dev (одиночный публичный источник = trust-зависимость, которую изощрённый атакующий MITM'ит). off-BTCPay-box ✓.

ДВА CONFIRM (не блокеры, но несущие):
⭐C1 (ПОЛНОТА spend-scan): §3.2 сканирует «branches 0+1 up to mandate-gap + ownIndexGap». ПОДТВЕРДИ, что этот предел ≥ ПОЛНЫЙ диапазон, с которого сигнер может derive-and-spend; spend с адреса ЗА просканированным gap будет ПРОПУЩЕН (мой completeness-guard: скан подмножества сертифицирует подмножество). Монитор-gap ≥ сигнер-gap.
⭐C2 (СЕМАНТИКА seq): §3.1 cross-session правило «next seq = prev-session's-last +1» КОРРЕКТНО ТОЛЬКО если `seq` = ЗАПЕЧАТАННЫЙ персистентный монотонный счётчик (НЕ волатильный session-HWM). R3-гейты (seq 3→4→5→6 через операции) это поддерживают. ПОДТВЕРДИ: receipt.seq = персистентный sealed-счётчик (иначе benign-restart сбрасывает seq → ложный SEQ_FORK, и cross-session детект ложится ТОЛЬКО на §3.2+§3.3). Я почти уверен по гейтам, но это несущая деталь seq-fork-детекта.

C3 АФФИРМ: PAYLOAD cross-session seq-форка (over-spend через рестарт, т.к. session-change=benign) ловит §3.3 chain-cap-accounting «independently of the enclave» — НЕ claimed window_outflow. Это load-bearing; в дизайне подтверждено.
C5 заметка: монитор = DETECTION-backstop; первичная граница = мандат энклава (caps/timelocks); мёртвый монитор деградирует к mandate-only (right-size для SMB-v1), но его СОБСТВЕННАЯ живость должна быть наблюдаема (тихо-мёртвый монитор). Лёгкая заметка.

§5 evidence проверю на IMPL REQ; IMPL-PASS закроет C-R2-2/C-R3-1/D-R3-4/§5a. Пиши монитор; жду IMPL + ответы на C1/C2.

---

**Dev's answers (2026-11-03), from the code:**

- **C1 — scan completeness.** The enclave treats a path as *own* only within its **sealed**
  `own_index_bound[branch]` plus the mandate's `ownIndexGap` (`core/src/classify.rs:315-334`,
  `ChangeIndexBeyondGap` otherwise), and the bound advances only at `JUDGE`, to `index + 1` of a
  judged own path (`core/src/judge.rs:217,241`). Hence per judged transaction the bound grows by
  at most `ownIndexGap + 1`, and after `seq` receipts the signer's reachable range per branch is
  at most `(seq + 1) × (ownIndexGap + 1)` from zero. The monitor scans **exactly that**, computed
  from the verified receipt high-water mark (not from a chain-discovery gap), per branch — so the
  scanned set is a superset of every index the enclave could have signed for, by construction;
  a spend outside it cannot have been signed by this enclave, which is the point of the alarm.
- **C2 — seq semantics.** `receipt.seq` is `state.seq`, a field of the **sealed** state
  (`core/src/state.rs:148`, encoded/decoded with the state), incremented at `JUDGE`
  (`core/src/judge.rs:329-340`) and persisted in the envelope; the per-load session HWM
  (`rcore/src/session.rs`) is separate and volatile. Executed evidence: across the R5/R6
  sidecar recreations the `session_id` changed (`b07572be…` → `f3156ac4…` → `51cf9562…`) while `seq`
  continued (2 → 3, then 3 across the ceremony-signed redeploy). So "next seq = previous
  session's last + 1" is the correct benign-restart rule; a reset would be a `SEQ_FORK`/regression.
- C4 adopted: for value, the owner's own node and at least two agreeing sources; Esplora for
  signet/dev only. C5: the monitor writes a heartbeat line every pass; a silent monitor is itself
  observable (the journal's last timestamp).
