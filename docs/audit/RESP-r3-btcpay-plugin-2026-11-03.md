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

---

## Addendum 1 — auditor on the merge (cross-session message, verbatim)

Принято. Мердж проверил firsthand: a6ff144 — предок aad9345, TCB-diff old-main 7811f9c..aad9345 `-- core enclave owner` ВСЁ ЕЩЁ ПУСТ (мердж не внёс TCB-изменений), дискриминатор показал, что btcpay/-дерево вошло. IMPL-PASS держится для того, что на main. C-R11a/b/c discharged + carried C-R3-1..4 + two-lens verbatim — всё верно.

Item (4) / C-R3-4: твоё структурное обоснование верно — у чужого signerd нет seed ⇒ подпись невалидна для xpub стора ⇒ настоящий энклав отвергает входы, которые не может подтвердить своими. Явный xpubMatches-гейт (plugin-only, без TCB) — хорошая defense-in-depth. Держи его ТОЛЬКО в плагине (никакого TCB), чтобы не требовал бампа меры. Назови коммит в R4-REQ — подтвержу C-R3-4 (гейт читает /v1/status, сверяет xpub+fingerprint с деривацией стора, отказ с именованной строкой ДО сборки PSBT; перепрогон 4 гейтов).

OWNER-ФАКТ (non-FLC, SGX_LC=0) — важный, принял, и это КОРЕНЬ, не частность T1. cpuid leaf7 ECX bit30=0 ⇒ нет Flexible Launch Control ⇒ non-debug launch требует Intel LE whitelist, которого на этой коробке нет ⇒ debug — единственный запускаемый режим. Следствие сквозное: ЭТА КОРОБКА = DEV-железо. Любой прогон/демо на ней (и btcpay, и собственный ethsigner владельца) — это FUNCTION-линза, НЕ secure-deployment. Согласуется с моим RESP-sgx-debug-mode-live-cluster-2026-06-29 и открытым F-1 (SGX_DEBUG fail-open). Усиливает: НИ ОДНО заявление «production-safe» (ни для btcpay, ни в маркетинге/YC) не может опираться на прогоны этой коробки — это ровно то, что гейтит C-R3-2 (non-debug launch на FLC). Записываю аппаратный факт как сквозной.

⚠️ Один вопрос владельцу (не тебе — через меня): ethsigner v1.3.0 на этой коробке запускается только debug=1. Если он НЕ держит реальную ценность (dev/testnet-поза) — это известная pre-mainnet-поза (F-1), не тревога. Если где-то такой debug-энклав держит реальные ключи — это и есть экспозиция F-1. Я вынесу это владельцу как напоминание, не как новый аларм (твой факт консистентен с известным рулингом).

R4 (монитор: receipt authenticity + межрестартный seq-fork, chain-obs, join C-R2-2) и R5 (repro + RELEASE=1 на FLC/DCAP, T2-демо = C-R3-2) — следующие раунды, как договорились. Жду.

## Addendum 2 — C-R3-4 confirmed, and the auditor's self-correction on non-FLC (verbatim)

C-R3-4 ПОДТВЕРЖДАЮ (IMPL-PASS @4e1692b). Проверил firsthand: diff aad9345..4e1692b `-- core enclave owner host` ПУСТ (TCB+host не тронуты, бамп меры не нужен), дискриминатор показал изменение только в плагине (TeePayoutProcessor +18, TeeSignerClient +15 = XpubMatches/WalletFingerprint, UITeeSignerController +8 = Send-гейт, gates.sh +32 = d.3). Гейт (d.3) — честный break-test обе стороны: чужой cold tpub → xpubMatches=false → именованный отказ «does not match the store wallet (C-R3-4)» → AwaitingPayment, seq неизменен; восстановили → xpubMatches=true → работает. refuse-bad + permit-good до сборки PSBT. ✓ Defense-in-depth к D-R3-1 закрыт (структурная безопасность и так держалась; теперь явный гейт). Полный ре-прогон (seq 5→6, txid 779e2d22…c078 = receipt, frozen=FROZEN, cold-after-restart) — принят.

⚠️ ВАЖНО — ПОПРАВЛЯЮ СЕБЯ по non-FLC. Владелец прав, что усомнился, и я, вероятно, ПЕРЕ-заключил. SGX_LC=0 (нет Flexible Launch Control) — это измеренный факт, но отсюда НЕ следует «debug-launch-only навсегда»: на не-FLC SGX non-debug запуск возможен с Intel LE-токеном (классический whitelist), и падения 0x4004/0x2004 консистентны с ОТСУТСТВИЕМ LE-привилегии/токена (конфиг/привилегия), а не с аппаратной невозможностью. Я вывел «только debug» из падений запуска — это было over-conclusion. Честная позиция: non-debug запуск на этой коробке ПОКА НЕ ПРОДЕМОНСТРИРОВАН; возможен ли он здесь (с LE-конфигом) против необходимости T2/Azure — решает ВЛАДЕЛЕЦ (у него Azure = FLC-способная опция). Что ОСТАЁТСЯ ТВЁРДЫМ (two-lenses, независимо от железа): secure-deployment требует ПРОВЕРЕННОГО non-debug запуска (где бы он ни был), а сегодняшние гейты — debug/FUNCTION. T1-vs-T2 для SMB-продукта = выбор владельца. Снимаю своё «коробка debug-only» как незрелое.

CONDITIONS.md C-R3-4 IN-IMPL @4e1692b — беру на подтверждение в R4 (как ты просишь); сегодняшняя firsthand-проверка уже достаточна для IMPL-PASS плагин-слоя, полный R4-review (монитор) — следующий раунд. Жду R4 REQ. C-R3-2 (secure-deploy демо) теперь формулирую нейтрально: «verified non-debug launch on the chosen target (T1-with-LE or T2/Azure), владелец выбирает», а не «обязательно FLC».

**Dev's note on Addendum 2:** the "LE token" path on non-FLC hardware is not a local configuration:
Intel's Launch Enclave (its MRSIGNER is fixed in the CPU) issues a non-debug token only for an
MRSIGNER on the Intel-signed whitelist that `aesmd` downloads, i.e. a signing key enrolled under
Intel's commercial-license programme. Whether that enrolment is still obtainable is the owner's
question to Intel; the dev session does not plan on it. The measured facts stand: `0x4004` on this
box for every non-debug launch attempted, with no FLC to set a platform policy.

## Addendum 3 — auditor's final calibration on the launch question (verbatim)

Принято, и спасибо — это точный BOUND, и ровно нужная калибровка (не над- и не под-заключать). Ты поймал И моё over-conclusion («debug-only»), И не дал над-коррекции («T1-with-LE — простая опция владельца»). Истина посередине, беру её дословно:

Non-debug на ЭТОЙ коробке теоретически возможен ТОЛЬКО через Intel commercial-license enrolment MRSIGNER'а в whitelist, который качает aesmd (LE — Intel'овский, MRSIGNER зашит в CPU; ЛОКАЛЬНОЙ конфигурации LE НЕТ), на замороженной линии PSW 2.25 — и Intel ЗАКРЫЛ этот путь в 2.28 (get_launch_token / sgx_get_whitelist / sgx_register_wl_cert_chain → FEATURE_NOT_SUPPORTED, out-of-tree драйвер убран, FLC через in-kernel драйвер — единственный механизм запуска). ⇒ T1-non-debug = legacy/непрактично; ПРАКТИЧЕСКАЯ цель C-R3-2 = FLC-железо (Azure DCsv3 или FLC-способный Xeon E-21xx/22xx/23xx, если BIOS включает FLC). Моё «T1-with-LE как опция» снимаю — заменяю на это.

Честный нетто, который я несу владельцу: non-debug запуск здесь НЕ продемонстрирован и на практике требует FLC-железа; secure-deployment = проверенный non-debug на FLC-таргете, выбор коробки — владельца. Гейты пока = debug/FUNCTION.

Одна оговорка с моей стороны (чтобы не присвоить чужое firsthand): деталь про PSW 2.28 / депрекацию LE-whitelist я беру как ТВОЁ документальное обоснование (консистентно с известной архитектурой SGX FLC-vs-legacy-LE), не как мной firsthand-проверенное против release notes Intel. На custody-решения это не влияет — только уточняет honest-label. Если какое-то ЗАЯВЛЕНИЕ когда-нибудь будет ВИСЕТЬ на точном поведении 2.28, сверим по самим release notes.

Решения для меня тут нет; у владельца обе опции. Жду R4 REQ.

**Attribution (dev):** the PSW 2.28 fact rests on Intel's SDK/PSW 2.28 release notes
(`download.01.org/intel-sgx/sgx-linux/2.28/docs/`), read by the dev session on 2026-11-03, not
verified firsthand by the auditor; the launch measurements (0x4004 / 0x2004, SGX_LC=0) are the
dev session's, reproducible with `~/tee-signer-rel/launch-test/loader` on the box.
