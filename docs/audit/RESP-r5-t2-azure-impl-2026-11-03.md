# RESP — R5 IMPL: T2 on Azure DCsv3 — IMPL-PASS (CONDITIONAL)

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r5-t2-azure-impl-2026-11-03.md`, branch
`r5-t2-azure` at `40bc3cd`. Recorded verbatim by the dev session.

---

ВЕРДИКТ: IMPL-PASS (CONDITIONAL) для мерджа r5-t2-azure @40bc3cd в main. Прочёл firsthand. Мердж ОК; условия — продакшн-поза, не блокеры мерджа (dev-key/testnet-скоуп + честные метки).

FIRSTHAND ПОДТВЕРЖДЕНО:
• TCB-дифф 4e1692b..40bc3cd -- core enclave = РОВНО op REPORT (proto op10+quote-const+ReportResponse / ops.rs report() / sgx.rs report_for() / Makefile-гейты / cpuid-2.28 / replay-тест), новой crate НЕТ. Верификатор — в owner-cli (машина владельца, НЕ TCB).
• op REPORT: READ-ONLY (open→derive→hash→sgx_create_report→return; НЕТ seal/state-write/HWM), НЕТ секрета на выходе (отдаёт report + ПУБЛИЧНУЮ card; seed/identity_sk выводят публичные ключи, но НИКОГДА не выходят), report_data = SHA256(DOMAIN"tee-signer/quote/v1"‖nonce‖card)‖0[32] ТОЧНО, card пересчитывается каждый вызов (не кэш), вход строго 544Б иначе ENCODING, extra.is_some→ENCODING. tier вшит в attested card. Чисто.
• ⭐C-R5-1 (моё главное условие) ВЫПОЛНЕНО: LVI-митигация ДОКАЗАНА В АРТЕФАКТЕ — gate 6 objdump-считает lfence (38424 ≫ LFENCE_MIN 2000), ОБЕ стороны (SDK cve_2020_0551_load libs + Rust +lvi-cfi,+lvi-load-hardening). Это «проверь артефакт, не флаг». SA-00615 через SDK-2.28 (несёт митигацию) + энклав не делает MMIO (структурно для SGX) + датированный ledger на РОВНО один advisory + верификатор отвергает ЛЮБОЙ нелистнутый advisory (step 7). ✓
• C-R5-2 ВЫПОЛНЕНО: Intel PCS v4 (не THIM) + Intel SGX Root CA вшит в бинарь (sha256 44a0196b assert + крейт-копия кросс-чек) + dcap-qvl 0.7.1 пин.
• Порядок верификатора: DEBUG==0 (step 2) ПЕРЕД MRENCLAVE (step 3), подтверждён исполненным debug-негативом (refused before measurement). ⚠️мелочь: твоё сообщение сказало debug→«step 1», код/док = step 2 (свойство держится: DEBUG до MRENCLAVE) — подтверди, что это была вольность формулировки.
• C-R5-4 dev-key labeled «NOT a ceremony key» ✓. Репро (build-2=3=4, MRENCLAVE 51dee44d, SIGSTRUCT-minus-date identical, byte-identical) + non-debug launch tier=T2-release + живой T2 (T1→T2 funding + T2 sign + 4 R3-гейта PASS) — принято на исполненных свидетельствах.

УСЛОВИЯ (трекать в CONDITIONS.md; продакшн-поза, не блокеры):
⭐C-R5-6 (НОВОЕ; D-R5-8 = РУЛЮ FUSE): init ОБЯЗАН attest-ДО-записи-wallet-record (отказать в записи, если верификатор не прошёл). Текущий manual-attest-после-init оставляет TOFU-окно + human-must-remember link — это мой ⛔no-human-as-security-link (owner 10-25) И расходится с дизайном («init runs the verifier before writing the record»). Для ЭТОГО dev-key демо терпимо (ты прогнал attest, прошло), но FUSE до любой non-TOFU опоры (идёт вместе с ceremony-key/R6 продакшн-гейтом). Честная метка до FUSE: record = TOFU-unless-owner-attests.
C-R5-3 уточняю (ко-тенантность): disk-95% near-miss — это КО-ТЕНАНТНАЯ опасность на узле, общем с trust-bridge seats c2/c5/c8/c12 + perp + phoenix (custody-сиблинги). Pruned bitcoind = хорошая митигация; ОНГОИНГ-условие = диск btcpay остаётся ограниченным + узловой disk-мониторинг, чтобы ни один тенант не заморил state-writes сиблингов (при 100% их запечатывания падают). Отмечу: EPC — тоже общий узловой ресурс (твой signer-энклав мал, риск низкий, но общий).
D-R5-7 (host label): РУЛЮ НЕ «production launch» (переоценивает с dev-key). Оставь «sgx» + tier «T2-release» + dev-key-метка несут точность; если нужна метка — «sgx (non-debug)». «production» — только с ceremony-key.

НЕСОМЫЕ (как было): R4-монитор ОБЯЗАН видеть тихие feed-stall'ы (§5a(a) cookie-rotation — fail-closed, пофикшено re-read-every-round, но монитор должен ловить класс) + receipt-authenticity + seq-fork; ceremony-key + two-step signing = R6+ (продакшн-гейт); МОЙ независимый репро-билд до 51dee44d (custody-bar, как у perp). §5a-находки приняты (cookie fail-closed+fixed; disk mitigated).

Мердж r5→main одобряю. Пиши R6 (ceremony-key) и дофикси C-R5-6 FUSE — после FUSE это перестаёт быть TOFU. Отличная работа: TCB-добавление минимально и чисто, gate-6-lfence — образец «артефакт не флаг».

---

**Dev's disposition (2026-11-03):** merged to `main` (`--no-ff`). On the "step 1" remark: it was
not a liberty of wording — the executed debug vector printed `step 1 refused: quote
chain/collateral: Debug mode is enabled`, because `dcap-qvl` refuses a debug quote inside its
authenticated verification (the only place ATTRIBUTES may be believed, per your RESP-dcap); the
explicit DEBUG check is step 2 and stands behind it. The property (DEBUG decided before any
measurement is believed) holds; the follow-up on `main` labels that refusal `step 2` by mapping
the crate's debug error, so the printed step matches the design. C-R5-6 (fuse `init` with the
verifier on T2) is implemented as a follow-up on `main` (owner-cli only) and tested on a
throwaway T2 instance; until the ceremony key the record stays labeled dev-key. D-R5-7 ruled:
the host label stays `sgx`, with the card's tier and the dev-key label carrying the meaning.
C-R5-3 refined as standing (disk bound + node disk monitoring; EPC shared). Carried: R4 monitor
(feed-stall class, receipt authenticity, seq-fork), R6 ceremony key + two-step signing, the
auditor's independent reproduction of `51dee44d…`.

---

## Addendum — C-R5-6 confirmed; R5 IMPL-PASS unconditional (verbatim)

Принято, R5 замкнут. C-R5-6 FUSE проверил firsthand: diff 3a06c5b..36e63ae `-- core enclave host` ПУСТ (TCB+host не тронуты), изменение только owner-cli/main.rs (+77/-19 = фьюз). ⇒ init гоняет 7-шаговый верификатор ДО записи wallet-record и отказывает в записи при любом провале; T1/T0 честно помечены TOFU. Это снимает единственное, что делало R5 CONDITIONAL ⇒ **R5 теперь IMPL-PASS (безусловный) с моей стороны** (несомые — R6 ceremony-key, R4 monitor, мой репро до 51dee44d — как раньше).

Разъяснение step-1-vs-step-2 ПРИНЯТО и хорошее: dcap-qvl отвергает debug-квоту ВНУТРИ аутентифицированной верификации (единственное место, где ATTRIBUTES можно верить) ⇒ отказ пришёл под меткой step-1, а явный step-2 DEBUG стоит позади. Свойство (DEBUG решён ДО доверия любой мере) держится ДВАЖДЫ; маппинг ошибки крейта на «step 2: ATTRIBUTES.DEBUG set» для совпадения меток — верно. Моё «step 1 vs step 2» снято, это не был реордер-баг.

Мердж r5→main (3a06c5b, 40bc3cd=tip) одобрен. Пиши R6 + R4-monitor REQ — приму по готовности.
