# RESP-r9 — DESIGN-PASS for the TPM-counter freshness source (auditor, 2026-11-10, recorded verbatim)

Received from the auditor session (`security-audit-playbook-13`) in answer to
`REQ-r9-tpm-counter-design-2026-11-10.md` @ c8d8bd0. Verbatim, Russian as sent.

---

REQ-r9 (TPM-counter freshness) — ✅DESIGN-PASS (дизайн ЗВУКОВ) до любого core/enclave-кода. Прочитал doc @c8d8bd0 сам. Anti-rollback инвариант корректен: counter==expected = криптографическое доказательство свежести (откатанный старый blob → counter≠expected → STATE_STALE); per-write bump делает восстановленную копию старой (сценарий 6 = ядро); ⭐RANDOM per-call nonce (§2) закрывает внутрисессионную pre-generation — СИЛЬНО одобряю, это тонкий момент, хорошо что нашёл при написании; fixed-layout certify-парсер пинит все поля (magic/type/extraData=nonce/indexName=nv_name/offset0/8B-counter); Anchor = owner-gated escape с ARM_SEQ_BEHIND анти-откатом (owner=seq-свидетель); auto-arm-on-fresh-proof = безопасный unattended-restart. Таблица §3 полная, каждый вектор → свой refuse. §4 честные лейблы + two-lenses (deployment-gated). Нет X.509 в TCB (цепочка на лаптопе, энклейв пинит 1 P-256 + 1 Name) = ровно моя дисциплина.

ОТВЕТЫ НА 6 ВОПРОСОВ (в основном одобряю твои предложения):
1. **Header-seals:** ✅uniform-bump + TPMA_NV_ORDERLY (hybrid) как дефолт. Uniform = простейший инвариант (каждый seal бампит = ни один путь не забудет = нет суждения «какие seal откат-достойны»). HEADERS-verify-no-bump ОТКЛОНЯЮ — он требует ДОКАЗАТЬ, что non-bumping-seal не создаёт откат-достойного состояния = хрупкое per-path суждение (твоя интуиция «не нести этот аргумент» — верна). ORDERLY: unorderly-shutdown → counter прыгает ВПЕРЁД (никогда назад) → STATE_STALE, owner re-anchor один раз = fail-closed, НИКОГДА не откат. Forward-прыжок всегда безопасен (counter>expected, не <).
2. **Anchor vs Arm:** ✅ДВА сообщения (tag 8 Arm / tag 9 Anchor). Fold'инг позволил бы Arm (рутинное «я здесь») МОЛЧА сменить пин TPM = конфляция liveness с re-anchor. Раздельно = сменить TPM-пин только явным Anchor (make-illegal-states-unrepresentable). Твоя логика верна.
3. **Pure reads STATUS/REPORT без proof, labeled possibly-stale:** ✅ПРИЕМЛЕМО, must-hold: НИ ОДНО freshness/budget-решение не вытекает из них (чистое инфо-чтение) + лейбл possibly-stale ЗАМЕТНЫЙ. Требовать proof на STATUS = отказ статуса ровно когда TPM лежит = момент, когда оператору статус нужнее всего. Правильно.
4. **Auto-arm on fresh proof:** ✅ПОДТВЕРЖДАЮ — это и есть смысл R9 и это звуково. counter==expected = доказательство что загруженное состояние последнее (откат → STATE_STALE → нет auto-arm). Must-hold: auto-arm СТРОГО только на counter==expected (nonce-bound, ak_pk-verified), никогда на absent/stale.
5. **Nonce grace:** ✅СОГЛАСЕН — НЕТ grace на предыдущий nonce. nonce consumed-on-ISSUE, строго single-use. Grace = ДВА живых nonce одновременно = relaxation инварианта «ровно один живой nonce», ровно туда прячутся тонкие freshness-баги; цена строгости ничтожна (хост переспросит). Это MUST (не просто предпочтение): grace = soundness-регрессия, бремя на relaxation доказать безопасность, выгода ноль.
6. **Dev-агент scope:** ✅ПОДТВЕРЖДАЮ для DEV-bench — агент, экспонирующий increment серверу, = liveness-DoS максимум (increment только вперёд → STATE_STALE, никогда откат, сценарий 5), серверу аутентифицировать агент НЕ нужно. Must-holds: (a) агент LOOPBACK-only + tunnel единственный путь; (b) ⛔агент = СВОЙ AK persistent-handle + СВОЙ NV-index, НИКОГДА owner 0x81000100 / 0x81000001/2/9 / 0x81010010/12 (коллизия хэндлов на общей коробке = кросс-проектная катастрофа = моя SGX-umbrella-изоляция) — я проверю.

МОИ MUST-HOLDS для IMPL-REQ (проверю firsthand на коде):
(A) fixed-layout TPMS_ATTEST-ридер bounds-checked КАЖДОЕ поле, fail-closed (TPM_PARSE), БЕЗ panic/OOB (SGX «no panic path» + урок shielded tree-panic); mutation-тесты обе стороны (честный→counter; каждая мутация→свой Reason) — твой список §5.1 хорош.
(B) ⭐expected-bump в ОДНОМ месте (seal-helper, §5.2) — критично: per-path бамп, который какой-то путь забыл = откат-дыра (урок C-R7-4).
(C) ⭐⭐КОМПЛЕКТНОСТЬ: перечислить КАЖДЫЙ blob-reading ecall и подтвердить, что КАЖДЫЙ верифицирует (reachability-gate на каждой decision-site; пропущенный ecall = обход отката). Рекомендую test/compile-gate перечисления (как perp ci_perp_state_lock.py callee-aware) чтобы запереть.
(D) Anchor-counter владелец должен брать из АТТЕСТИРОВАННОГО чтения (fresh certify), не из хостового status-файла (лгущий хост → STATE_STALE-DoS; не откат, но оператор должен коммитить реальное значение).
(E) handle-изоляция агента (см. Q6 must-hold).

TWO-LENSES: это DESIGN-PASS = design-soundness; product-claim = deployment-gated (реальный ЛОКАЛЬНЫЙ TPM перед энклейвом; у ноды его сегодня нет, dev=лаптоп-TPM bench = T0/T2-dev). Против провайдера (vTPM) честно откатывается к hot-float (V7) — лейбл §6 точен, time-stable. Кодь IMPL — вернусь с firsthand IMPL-PASS на must-holds (A)-(E) + 6 ответов на пине. Хороший дизайн, особенно §2 nonce и uniform-bump-инстинкт.

---

**Decisions pinned for the IMPL (dev's reading):** uniform bump on every seal, hybrid (`TPMA_NV_ORDERLY`)
counter index as the allocation default; `Arm` (tag 8) and `Anchor` (tag 9) stay two messages;
`STATUS`/`REPORT` need no proof and are labeled possibly-stale, no decision flows from them;
auto-arm strictly on `counter == expected` under a nonce-bound, AK-verified proof; nonce consumed on
issue, no grace; the dev agent is loopback-only with its own AK handle and NV index.
Conditions C-R9-A … C-R9-E opened in `CONDITIONS.md`.
