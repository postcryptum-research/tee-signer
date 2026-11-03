# RESP — R3 BTCPay plugin, docker sidecar, four executable gates: IMPL review

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r3-btcpay-plugin-2026-11-03.md`, branch
`r3-btcpay-plugin` at `a6ff144`. Recorded verbatim by the dev session.

---

RESP-r3-btcpay-plugin-2026-11-03 (записывай дословно). ВЕРДИКТ: IMPL-PASS — мерджить btcpay/ (plugin + docker fragment + e2e) + одиночный host-side signerd fix в main @a6ff144. Блокеров нет. Всё проверено firsthand @a6ff144 vs main 7811f9c в собственном пинованном клоне.

ЧТО ПРОВЕРИЛ FIRSTHAND:
1. TCB-DIFF ПУСТ подтверждён (с дискриминатором — я в этой сессии дважды обжёгся на пустых diff'ах, поэтому проверял, что инструмент вообще показывает изменения): полный diff 7811f9c..a6ff144 = 25 файлов / 1426 строк недоверенной поверхности (C#-плагин, docker, gates.sh, docs, host/signerd), а срез `-- core enclave owner` ПУСТ. ⇒ анклав байт-в-байт с main, R2-IMPL-PASS держится; это ревью недоверенной интеграции + одного host-feed-фикса, не TCB.
2. host/signerd/src/main.rs (§1a): чистая feed-логика поиска точки стыковки; анклав РЕШАЕТ (op::HEADERS валидирует каждый пробник), FORK_PROBE_DEPTH=32 ограничен окном, которое анклав вообще может принять; реорг глубже maxReorg → фриз анклава СОХРАНЁН (core не тронут) + fail-safe Err «owner must re-pin the checkpoint» (не молчаливая неверная стыковка, не бесконечный ретрай). Старую логику best-10 РЕТАЙРИТ (diff её удаляет). Чинит реальный R2 liveness-баг. В main безопасно.
3. Граница плагина: TeeSignerClient.cs = РОВНО 3 вызова (GET /v1/status, POST /v1/sign, GET /v1/receipts). Ни mandate, ни freeze/unfreeze, ни policy из плагина НЕ достижимы. ⇒ недоверенный плагин не может авторизовать трату (mandate = owner-key вне полосы). Fee-fallback = под потолком mandate анклава (TeeSignerSettings:15 «the enclave's mandate is the fee ceiling that is enforced») ⇒ хост не превысит. IsHotWallet-отказ присутствует (Plugin.cs:11), а gates доказывают холодный кошелёк + ноль seed-строк.
4. gates.sh: реально утверждает все 4 гейта на живом стеке; сильная связка (d.1) = enclave seq растёт И receipt txid == broadcast txid (хост не подделает без реальной подписи анклава); (d.2) freeze → AwaitingPayment, seq неизменен, отказ назван (FROZEN). Мелочь: S1 (UI-seed) утверждён ВЫВОДОМ из (a)+§2b, не исполнен напрямую — приемлемо (IsHotWallet=false структурно гасит HotwalletSafe.TryUnlock, а (a) проверен напрямую); прямой S1-ассерт = nice-to-have, не блокер.

§5 — ВСЕ ПРИНЯТЫ:
• D-R3-1 (repoint на другой signerd по API-key): принимаю. Это config/liveness, средства целы — у чужого signerd НЕТ запечатанного seed ⇒ он не подпишет xpub стора, а xpubMatches (status) это ловит. V1-эквивалент. Defense-in-depth: подтверди, что путь sign/payout гейтит на xpubMatches (структурно и так безопасно — нет seed, нет валидной подписи).
• D-R3-2 (fee-fallback, дефолт 10): принимаю. Потолок комиссии — mandate анклава (enforced), fallback лишь убирает «мёртвый эстиматор → гарантированный FEE_RATE отказ» (liveness). Хост не превысит.
• D-R3-3 (10 отказов гасят процессор для этого payout): принимаю, сток-семантика; liveness, на безопасность не влияет.
• D-R3-4 (подпись чека НЕ проверяется плагином): принимаю, корректно отложено на R4. Проверка недоверенным плагином = театр. Сегодняшняя связка (seq+txid+mempool) достаточна для FUNCTION-гейта; криптографическая аутентичность чека + межрестартный seq-fork detection = R4 (несомое обязательство).

⚠️ HONEST-LABEL / RELEASE=1 — ДВЕ ЛИНЗЫ, явно (не блокер мерджа, но запиши):
Правка README верна и честна. НО фиксирую scoping: гейты прошли с анклавом в DEBUG (non-debug launch на T1/non-FLC падает: 0x4004 SERVICE_INVALID_PRIVILEGE / 0x2004 INVALID_ATTRIBUTE). ⇒ гейты доказывают FUNCTION (интеграция маршрутизирует верно, уважает freeze, держит кошелёк холодным), НЕ безопасную продакшн-позу. Конфиденциальность/аттестация анклава требуют НЕ-debug запуска на FLC-железе, чего T1-прогон не исполнял. Это деплой-предусловие (честно помеченное), не дефект кода и не блокер мерджа. Для SMB / не-около-мейннета — приемлемо как задокументированное предусловие. Не смешивай function-pass с secure-deployment.

НЕСОМЫЕ ОБЯЗАТЕЛЬСТВА (мердж не блокируют): (1) R4-монитор (D-R3-4 + межрестартный seq-fork, chain-obs); (2) secure-deployment демо на FLC + non-debug до заявления «продакшн-безопасно» (= R5 repro/RELEASE на FLC, §6); (3) nice-to-have: прямой S1-runtime-ассерт; (4) подтвердить xpubMatches-гейт на пути подписи (defense-in-depth к D-R3-1). §6 out-of-scope (PayJoin / R4 / R5 / hw owner-key) — принято как вне этого ревью.

Итог: IMPL-PASS @a6ff144, bound to ref. Мердж безопасен (TCB не тронут, host-fix fail-safe, плагин не может обойти анклав). Жду R4 и FLC-демо как следующие раунды.

---

**Dev's disposition (2026-11-03):** merged to `main` (`--no-ff`). C-R11a/b/c discharged in
`CONDITIONS.md`; carried as C-R3-1 (R4 monitor: receipt authenticity + cross-restart seq-fork,
chain observation), C-R3-2 (secure-deployment demo: non-debug launch on FLC before any
"production-safe" claim — R5), C-R3-3 (direct S1 runtime assert, nice-to-have), C-R3-4
(xpubMatches gate on the signing path, defense-in-depth to D-R3-1 — implemented as a follow-up
commit on `main`, untrusted plugin code, for the auditor to confirm in R4). The two-lens
scoping is adopted verbatim: the R3 gates prove FUNCTION on T1-debug, not a secure production
posture; that is the R5 deliverable.
