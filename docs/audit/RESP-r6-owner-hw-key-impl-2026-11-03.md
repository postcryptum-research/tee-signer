# RESP — R6 IMPL: owner key in the TPM, ceremony enclave-signing key — IMPL-PASS

**Date:** 2026-11-03 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r6-owner-hw-key-impl-2026-11-03.md` at `4eff209`.
Recorded verbatim by the dev session.

---

ВЕРДИКТ: IMPL-PASS для мерджа r6-owner-hw-key @4eff209 в main. Production-gate (C-R5-4) ВЫПОЛНЕН. Прочёл firsthand.

TCB неизменен ✓: diff main..4eff209 `-- core enclave/rcore enclave/Enclave` ПУСТ; r6 трогает owner-cli + Makefile(gate7+gendata/catsig) + enclave/ceremony/(pin) + docker + scripts — не код верификации анклава.

⭐C-R6-1 ✓ ПОЛНОСТЬЮ firsthand: owner-cli/Cargo.toml пинит `hw-signer rev=9fa47b6, default-features=false, features=["tpm"]` ⇒ компилируется ТОЛЬКО tpm-бэкенд. Дельта крейта 96d56ad→9fa47b6 = РОВНО feature-gated yubikey_piv (lib.rs +3 = `#[cfg(feature="yubikey-piv")] pub mod yubikey_piv`, yubikey/zeroize deps OPTIONAL, yubikey_piv.rs новый) — НИ ОДНОГО изменения tpm-бэкенда/трейта. ⇒ tpm-бэкенд, который btcpay компилирует, БАЙТ-В-БАЙТ мой аудированный 96d56ad. (108-файловый whole-repo дифф нерелевантен — ты пинишь КРЕЙТ по rev + default-features=false.) Твоё крейт-scoped утверждение было верным; подтвердил.

C-R6-2 ✓ keygen отвергает SRK 0x81000001 + чужой 0x81000002 + занятый 0x81000100; tss-esapi (owner-cli dep) только ЛИСТИТ handles, не evict'ит. Co-tenancy на TPM соблюдена.

Ceremony ✓ (принято на исполненных свидетельствах + дизайн, что я пропустил): RSA-3072 e=3 offline-ноут, AES-256-at-rest, НЕ на build-host; MRSIGNER 56b25ccb из modulus ДО подписи == sgx_sign dump; gendata-Hetzner→ceremony-sign.sh-ноут(sig verified под pinned-pub)→catsig; gate 7 MRSIGNER==pinned; compare build-3==build-5 MRENCLAVE 51dee44d BYTE-IDENTICAL (сравнение по measurement-covered SIGSTRUCT, signer/date исключены); sealed-state unseal под ceremony-signed (MRENCLAVE-seal); attest old-dev-pin→step4-refuse / --expect-mrsigner ceremony --pin→pass+re-pin+labeled; fused-init против dev-key→REFUSED "expected 56b2…". Всё, что я пропустил в R6-дизайне, исполнено.

D-R6-6 ✓ АФФИРМИРУЮ: rotate-owner-на-TPM = ТАЙМЛОКНУТОЕ ПОСЛАБЛЕНИЕ (pending_owner 329441=+144; старый keyfile-owner СТОИТ до активации; TPM-unfreeze POLICY_SIG-refused до тех пор; recovery может ОТМЕНИТЬ в окне) — это мандатный fail-toward-tightening / timelocked-loosening работает, ХОРОШО. ⚠️ЗАМЕТКА: живой T2-owner ВСЁ ЕЩЁ keyfile до блока 329441 — миграция-на-TPM В ПОЛЁТЕ (завершится на активации); throwaway-кошелёк (TPM-owner INSTALL/freeze/unfreeze/keyfile→POLICY_SIG) доказывает TPM-путь, когда активен.

Честная метка ✓: «ceremony key held by operator on laptop; production-safe = где оператор держит ключи (offline/HSM, PCR-seal), не code-gap» — верная two-lenses (CODE production-gate выполнен; OPERATIONAL key-custody — операторская).

НЕСОМЫЕ (мердж НЕ блокируют): (1) МОЙ независимый репро-билд до 51dee44d (custody-bar, как у perp) · (2) ⚠️yubikey_piv.rs (+297) НЕ аудирован мной И feature-gated-OFF в v1 (tpm-only) — когда scenario-2 включит yubikey-feature, нужен МОЙ review ДО использования (не шипить yubikey без него) · (3) PCR-seal deferred (keylogger-of-authValue остаток, labeled off) · (4) R4-monitor.

Мердж r6→main одобряю. Это замыкает R-серию до production-gate. Следующее: R4-monitor REQ + (когда plugged) YubiKey scenario-2 для моего review.

---

**Dev's disposition (2026-11-03):** merged to `main` (`--no-ff`). C-R6-1, C-R6-2 and C-R5-4
discharged; carried as C-R6-3 (the YubiKey PIV backend is reviewed by the auditor before scenario
2 enables the feature), C-R6-4 (PCR sealing deferred, labeled: the authValue keylogger residual),
the auditor's independent reproduction to `51dee44d…`, and the R4 monitor. The live T2 owner stays
the keyfile until block 329441; the activation is reported when it lands.
