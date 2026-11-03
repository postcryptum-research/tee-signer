# RESP — R5 design: T2 on Azure DCsv3 — DESIGN-PASS (CONDITIONAL)

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r5-t2-azure-design-2026-11-03.md`, branch
`r5-t2-azure` (ruled at the branch head the auditor named, `de7bc7b6`; the REQ text is identical at
`dd6f5c0`). Recorded verbatim by the dev session.

---

ВЕРДИКТ: DESIGN-PASS (CONDITIONAL) для §3 op REPORT + §4 verifier + §5 build + §6 deploy. Пиши код op REPORT. Прочёл firsthand на ГОЛОВЕ ветки de7bc7b6 (ты цитировал dd6f5c0; голова ушла вперёд на +docker-sidecar-скаффолдинг, потомок, REQ не менялся — рулю по de7bc7b6, пинь его). Pre-code подтверждён: enclave/-дельта = Makefile под SDK 2.28 + пустой placeholder sdk-cpuid-baseline-2.28.txt, кода op REPORT НЕТ; мера меняется ребилдом под SDK 2.28 = ожидаемо.

§3 op REPORT — PASS. Read-only, НЕ меняет state, НЕ выносит секрет (report_data=SHA256 над ПУБЛИЧНЫМИ card+nonce; card пересчитывается из конверта каждый вызов, не кэшируется; malformed→ENCODING; переиспользует sgx_create_report, нет новой crate). Чистое минимальное TCB-добавление. target_info/nonce untrusted-вход безопасны (плохой target_info = квота не сойдётся, не утечка).
§4 verifier — PASS. Порядок верный (chain+collateral → ⭐DEBUG==0 ПЕРЕД MRENCLAVE → MRENCLAVE==card==pinned → MRSIGNER/ProdID/SVN → card-sig+tier T2-release → report_data с нонсом верификатора → TCB-policy), на МАШИНЕ ВЛАДЕЛЬЦА (D-R5-3 верно: не рядом с противником). Негативы обе стороны (debug→2, nonce, swapped-xpub→6, wrong-MRENCLAVE→3, collateral-unreachable→refuse-not-warn).
§5 build — PASS. Repro (SIGSTRUCT минус header.date+подпись, MRENCLAVE-равенство, gate 5 исполним), ключ НИКОГДА в образе (mount на docker run), cpuid-baseline 2.28.
§6 deploy — PASS. loopback-only + SSH-туннель через Hetzner; СВЕЖИЙ T2-кошелёк (новый seed/identity) из T1 под мандатом = живое использование R3.

§7 рулинги: D-R5-1 card-hash+nonce ✓ (связывает всю identity, swapped-xpub падает @6, nonce=anti-replay). D-R5-2 MRENCLAVE-sealing ✓ (single-node, нет кластера/миграции; свежий seed ⇒ кросс-unseal не нужен). D-R5-3 pure-Rust dcap-qvl на машине владельца ✓. D-R5-4 TCB-policy §4.7 ✓ (no-silent-downgrade). D-R5-5 aesmd ✓. D-R5-6 dev-key labeled ✓.

УСЛОВИЯ (держать; проверю на IMPL):
⭐C1 (БЕЗОПАСНОСТЬ, главное): SW_HARDENING_NEEDED (D-R5-4) принимать ТОЛЬКО если сборка под SDK 2.28 НЕСЁТ требуемые advisory мягкие митигации (LVI/MMIO — SDK mitigation-флаги). Иначе принятие SW_HARDENING_NEEDED = принятие НЕ-митигированного анклава, держащего seed. Ice Lake DCsv3 вернёт SW_HARDENING_NEEDED — исключение валидно ЛИШЬ в паре с реальными митигациями в билде; ledger называет КОНКРЕТНЫЙ advisory-ID+дату. (Ровно мой LVI+artifact-check / SafeMath-always: статус «нужна-хардининг» ОК только когда хардининг СДЕЛАН.)
C2 (D-R5-3): пинь версию dcap-qvl + пинь корень доверия Intel SGX Root CA (не host/сеть-supplied); collateral верификатора — из Intel PCS v4 (авторитетный), НЕ Azure THIM.
⭐C3 (КО-ТЕНАНТНОСТЬ, ЖЁСТКО): sgx-node-3 CO-TENANT с trust-bridge seats c2/c5/c8/c12 + perp + phoenix (custody-сиблинги). btcpay-T2 строго в ~/tee-signer/ + loopback 7390/7392; НИКОГДА не трогай их dirs/ports/sealed-state. Единственные общие узловые ресурсы — /dev/sgx_enclave + /dev/sgx_provision + aesmd (узловой системный сервис, безопасно-общий: квоты независимы). Ты уже закрепил «ours vs not-ours» — делаю условием.
C4 (D-R5-6): dev-ключ помечен ЯВНО в wallet-record И в КАЖДОЙ status-строке; PRODUCTION-деплой ГЕЙТИРОВАН на ceremony-key + two-step signing (R6+); никакого «production-safe» на dev-key демо.
C5 (§5 IMPL): заполни sdk-cpuid-baseline-2.28.txt + подтверди, что каждый cpuid-сайт = символ SDK/IPP (D-R2-1); два билда MRENCLAVE-равны.

IMPL-доказательства (§8) проверю на IMPL REQ: non-debug tier=T2-release + DEBUG=0 в квоте; два билда MRENCLAVE-равны + SIGSTRUCT-дифф; attest-вывод с источником collateral+TCB-статусом; signet INIT/INSTALL/sign receipts; 4 гейта R3 на узле; негативы §4; D-11 стоимость на T2. Это и двигает C-R2-3/C-R10d/C-R1-3 + C-R2-4 + C-R3-2 + C-R1-1. Пиши op REPORT; жду IMPL REQ.

---

**Dev's disposition (2026-11-03):** conditions registered as C-R5-1..5 in `CONDITIONS.md`; the
`REPORT` op is written on this branch after this ruling (hard rule 1 honoured); C1 is taken as a
build requirement — the T2 image compiles the C side with the SDK's LVI mitigation and the Rust
side with the LLVM LVI target features, and the IMPL REQ carries the advisory ledger.
