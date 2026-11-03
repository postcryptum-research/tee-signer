# RESP — R4 IMPL: the owner's monitor — IMPL-PASS

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r4-monitor-impl-2026-11-03.md` at `a9c39fd`. Recorded
verbatim by the dev session.

---

ВЕРДИКТ: R4-monitor IMPL-PASS @a9c39fd, мердж ОК. ЗАКРЫВАЕТ C-R2-2 (cross-restart seq-fork), C-R3-1 (receipt-auth + chain-obs primary), D-R3-4 (receipt-sig), §5a feed-stall.

No-TCB подтвердил (diff main..a9c39fd `-- core enclave` ПУСТ; owner-cli monitor.rs+840 + seed-leak-vector[ТЕСТ-инструмент] + docs). Код проверил firsthand (live-T2 исполнение принимаю на твоём прогоне — нет доступа к Azure-T2):
• ⭐C1 superset-скан: range = (hwm_seq+1)×(ownIndexGap+1) на ОБОИХ путях (Esplora :263, node :367), min max_addresses. Ровно тот суперсет, что я подтвердил по enclave-bound. ✓
• receipt-sig verify под identity_pk (:181); SEQ_FORK (:211) + regression (:216) + session-continuity-benign-restart (:236) = D-R4-4 + C2. ✓
• ⭐FIX бага присутствует: :406 «outputs we created that are still unconfirmed — our own change in the mempool» + :418 mempool-spend-scan. ✓
• HWM-persist-ПЕРЕД-verdict (:45/:7); chain-obs из owner-node scantxoutset (:384). ✓ FREEZE на alarm-кодах (:501). ✓

⭐БАГ, найденный seed-leak-вектором (1-й pass ПРОПУСТИЛ вора, тратившего НАШУ неподтверждённую сдачу; node знал только confirmed) — это РОВНО C1-completeness класс, который я флагнул, всплывший на живом векторе. FIX (трекать СВОИ-неподтверждённые выходы) закрыл его, 2-й pass → SPEND_WITHOUT_RECEIPT + FREEZE. Хороший улов. Остаток (third-party-неподтверждённый-депозит, потраченный до подтверждения → виден на 1 pass после confirm) — помечен, mainnet-cost-вопрос (полный mempool-scan-for-incoming). Приемлемо пометить.

Chain source = Hetzner-node, НЕЗАВИСИМ от Azure-signer-host (D-R4-2 ✓); value/mainnet = owner-node ≥2-agree (C4). CHAIN_SOURCE WARN при rate-limit публичного Esplora + heartbeat-held (C-R4-3 измерено) ✓.

Рулинги:
• D-R4-7 RECEIPT_AMOUNT=WARN ✓ (пер-receipt = информативно; over-spend ловит CAP_EXCEEDED=ALARM; реальная привязка = txid+sig).
• D-R4-8 RECEIPT_GAP=WARN ✓ (gap WARN'ит; скрытую трату ловит SPEND_WITHOUT_RECEIPT=ALARM; консистентно с моим дизайном «gaps=WARN»).
• D-R4-9 --acknowledge <txid> ✓ CONDITIONAL: (a) OWNER-gated (не хост/не авто); (b) ПЕР-КОНКРЕТНЫЙ-txid (не blanket; НЕ маскирует alarm ДРУГОГО txid); (c) journaled/аудируемо; (d) НЕ авто-unfreeze (владелец размораживает отдельно; --acknowledge лишь гасит повтор-фриз по ревью'нутому txid). Подтверди (a)+(b)+(d).

Owner-рулинги АФФИРМИРУЮ: leaked-seed = total-loss by definition (монитор доказывает МЕХАНИКУ детектора, не защиту — вор с seed подписывает НАПРЯМУЮ, минуя анклав; freeze стопит дальнейшие АНКЛАВНЫЕ подписи, не вора). threat-model (компрометация) ОТДЕЛЬНО от continuity-model (аварии/recovery; --print-mnemonic now warned+confirmed) — честно и верно, монитор в threat.

⇒ Монитор = DETECTION-backstop (первичная граница = мандат анклава; мёртвый монитор деградирует к mandate-only, heartbeat его обнаруживает). Мердж r4→main одобряю. Несомые: D-R4-9 условия; third-party-unconfirmed остаток (mainnet-cost); мой btcpay-репро→51dee44d (не связан с R4, стоит). Это замыкает детектор-обязательства R-серии. Чистая работа.

---

**Dev's confirmation of D-R4-9 (a)(b)(d), from the code:** (a) `--acknowledge` is an argument of the
owner's `monitor` command on the operator machine; nothing on the signer host can set it, and no
code path acknowledges automatically. (b) It is a list of exact txids; the check is
`acked.contains(txid)` per spend (`monitor.rs`, the `SPEND_WITHOUT_RECEIPT` match arm) — any
other unreceipted txid still alarms. (c) Each new acknowledgement is journaled in the pass's notes
and persisted in `<journal>.ack.json`. (d) It never touches the freeze: `unfreeze` remains an
owner-signed message (keyfile or TPM), run separately after the human has looked — the executed
sequence was acknowledge → `OK` → `unfreeze --key …` → `applied`. Merged to `main`.
