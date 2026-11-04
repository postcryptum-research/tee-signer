# tee-signer enclave build (docs/ENCLAVE.md §7). Derived from the SDK's SampleEnclave Makefile
# through the lab of 2026-11-03 (docs/studies/NOSTD-ENCLAVE-LAB-2026-11-03.md).
#
#   make                 # HW, debug launch (the T1 box can do nothing else), test-init ON
#   make RELEASE=1       # HW, DisableDebug=1, test-init OFF, every gate asserted
#   make gates           # re-run the assertions on an existing enclave.so
#
# Every gate is a hard failure. Nothing here is advisory.

SHELL := /bin/bash
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
RELEASE ?= 0
CARGO ?= $(HOME)/.cargo/bin/cargo
RCORE_SRC := rcore
RCORE_DIR := $(RCORE_SRC)/target/x86_64-unknown-linux-gnu/release

include $(SGX_SDK)/buildenv.mk

ifeq ($(RELEASE), 1)
    SGX_DEBUG := 0
    RCORE_FEATURES :=
    CONFIG_DISABLE_DEBUG := 1
else
    SGX_DEBUG := 1
    RCORE_FEATURES := --features test-init
    CONFIG_DISABLE_DEBUG := 0
endif

# REQ-r7 §2.6 — the operator's opt-out, AT BUILD TIME ONLY: AUTO_ARM=1 compiles the pause after a
# restart OUT (rcore feature `auto-arm`): the enclave arms itself at load, its MRENCLAVE differs from
# the pinned one, STATUS and the identity card say `AUTO_ARM`. Never a runtime switch (a config, env
# or signerd flag would be root's to flip). The ceremony key never signs such a build (C-R7-8).
AUTO_ARM ?= 0
ifeq ($(AUTO_ARM), 1)
    ifeq ($(CEREMONY), 1)
        $(error AUTO_ARM=1 with CEREMONY=1: the ceremony key never signs an auto-arm enclave (REQ-r7 §2.6))
    endif
    RCORE_FEATURES += --features auto-arm
    AUTO_ARM_LABEL := AUTO_ARM (rollback pause compiled OUT — own MRENCLAVE, dev-signed only)
else
    AUTO_ARM_LABEL := pause-after-restart (REQ-r7)
endif

# C-R5-1: when the SDK's LVI mitigation is on (MITIGATION-CVE-2020-0551=LOAD — buildenv.mk adds the
# lfence-inserting assembler flags and links the mitigated trusted libs from lib64/cve_2020_0551_load),
# the Rust side is built with LLVM's LVI features too. RUSTFLAGS replaces the config.toml set, so it
# restates it. Gate 6 asserts the mitigation is in the artifact (lfence density), not just requested.
MITIGATION-CVE-2020-0551 ?= NONE
ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
    RCORE_ENV := RUSTFLAGS="-C relocation-model=pic --cfg aes_force_soft --cfg polyval_force_soft -C target-feature=+lvi-cfi,+lvi-load-hardening"
    LFENCE_MIN ?= 2000
else
    RCORE_ENV :=
    LFENCE_MIN ?= 0
endif

SGX_COMMON_FLAGS := -m64 -O2
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

######## Untrusted bridge (consumed by host/signerd through libenclave_u.a) ########
ifneq ($(SGX_MODE), HW)
    Urts_Library_Name := sgx_urts_sim
else
    Urts_Library_Name := sgx_urts
endif
App_Include_Paths := -IApp -I$(SGX_SDK)/include
App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
Bridge_Lib := App/libenclave_u.a

######## Enclave ########
ifneq ($(SGX_MODE), HW)
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
else
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := Enclave/Enclave.c
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS) -fstack-protector-strong
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack
# librcore.a sits inside the group right after -lsgx_tstdc (malloc/free/memalign/abort come from there).
# No --allow-multiple-definition, ever (gate 3).
Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -L$(RCORE_DIR) -lrcore -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=Enclave/Enclave.lds

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Config_Gen := build/Enclave.config.gen.xml
Enclave_Test_Key ?= Enclave/Enclave_private_test.pem

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
    Build_Mode = HW_DEBUG
else
    Build_Mode = HW_RELEASE
endif
else
    Build_Mode = SIM_DEBUG
endif

.PHONY: all target rcore clean gates bridge
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

target: $(Signed_Enclave_Name) $(Bridge_Lib) gates
	@echo "The enclave has been built in $(Build_Mode) mode (RELEASE=$(RELEASE))."

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_C_Objects) Enclave/Enclave_t.* App/Enclave_u.* $(Bridge_Lib)
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Rust staticlib ########
rcore:
	@echo "ARM POLICY: $(AUTO_ARM_LABEL)"
	@if [ "$(RELEASE)" = "1" ]; then \
	    echo "RUST (release, --locked, features: $(RCORE_FEATURES))"; \
	    cd $(RCORE_SRC) && $(RCORE_ENV) $(CARGO) build --release --locked $(CARGO_FLAGS) $(RCORE_FEATURES); \
	else \
	    echo "RUST (dev, --locked, $(RCORE_FEATURES))"; \
	    cd $(RCORE_SRC) && $(RCORE_ENV) $(CARGO) build --release --locked $(CARGO_FLAGS) $(RCORE_FEATURES); \
	fi
	@echo "RUST =>  $(RCORE_DIR)/librcore.a"
$(RCORE_DIR)/librcore.a: rcore

######## Bridge ########
App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
App/Enclave_u.c: App/Enclave_u.h
App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
$(Bridge_Lib): App/Enclave_u.o
	@ar rcs $@ $^
	@echo "AR   =>  $@"
bridge: $(Bridge_Lib)

######## Enclave objects ########
Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
Enclave/Enclave_t.c: Enclave/Enclave_t.h
Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
Enclave/%.o: Enclave/%.c Enclave/Enclave_t.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
# depends on the phony `rcore` so a changed Rust core always relinks (an mtime race left a stale .so once)
$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_C_Objects) rcore
	$(CC) Enclave/Enclave_t.o $(Enclave_C_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Config_Gen): $(Enclave_Config_File)
	@mkdir -p build
	@sed 's#<DisableDebug>[01]</DisableDebug>#<DisableDebug>$(CONFIG_DISABLE_DEBUG)</DisableDebug>#' $< > $@

$(Signed_Enclave_Name): $(Enclave_Name) $(Enclave_Config_Gen)
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "No enclave test key; generating $(Enclave_Test_Key) (dev only; a release key is a ceremony)"
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_Gen)
	@echo "SIGN =>  $@ (DisableDebug=$(CONFIG_DISABLE_DEBUG))"

######## Gates (docs/ENCLAVE.md §7) ########
# The Intel SDK's own trusted runtime (sgx_trts calls sgx_init_crypto_lib; tcrypto's IPP
# dispatcher probes the CPU) carries cpuid instructions that the SDK emulates from host-supplied
# tables when they trap inside the enclave. They cannot be removed without dropping the SDK
# runtime, so the gate is: every function in the FINAL enclave that contains cpuid is in the
# pinned SDK list (sdk-cpuid-baseline.txt) and the total equals the pinned count — nothing from
# Rust or from our C. A change in either is a REQ (docs/ENCLAVE.md §7).
# The list is per SDK version (the dev host runs 2.25, the T2 image 2.28); the instruction count
# is pinned beside it in <list>.count when it differs from the number of sites.
SDK_CPUID_LIST ?= sdk-cpuid-baseline.txt
SDK_CPUID_BASELINE ?= $(shell cat $(SDK_CPUID_LIST).count 2>/dev/null || LC_ALL=C sort -u $(SDK_CPUID_LIST) | grep -c .)
gates: $(Enclave_Name)
	@mkdir -p build
	@echo "GATE 1: cpuid sites in $(Enclave_Name) are exactly the pinned SDK set"
	@objdump -d $(Enclave_Name) | awk '/^[0-9a-f]+ <.*>:/{fn=$$2} $$NF=="cpuid"{print fn}' | sed 's/^<//; s/>:$$//' | LC_ALL=C sort -u > build/cpuid-sites.txt
	@if ! diff -q build/cpuid-sites.txt <(LC_ALL=C sort -u $(SDK_CPUID_LIST)) >/dev/null; then echo "FATAL: cpuid sites differ from $(SDK_CPUID_LIST):"; diff build/cpuid-sites.txt <(LC_ALL=C sort -u $(SDK_CPUID_LIST)); exit 1; fi
	@n=$$(objdump -d $(Enclave_Name) | awk '$$NF=="cpuid"' | wc -l); if [ "$$n" != "$(SDK_CPUID_BASELINE)" ]; then echo "FATAL: $$n cpuid instruction(s) in $(Enclave_Name), baseline $(SDK_CPUID_BASELINE)"; exit 1; fi
	@echo "GATE 2: no test-only symbols in a release build"
	@if [ "$(RELEASE)" = "1" ]; then \
	    if nm $(Enclave_Name) 2>/dev/null | grep -E -q 'test_init|hollow|reset_session|nosgx'; then echo "FATAL: test-only symbol present in a release enclave"; exit 1; fi; \
	fi
	@echo "GATE 3: no TEXTREL"
	@t=$$(readelf -d $(Enclave_Name) | grep -c TEXTREL || true); if [ "$$t" != "0" ]; then echo "FATAL: TEXTREL in $(Enclave_Name)"; exit 1; fi
	@echo "GATE 4: DisableDebug in the signed config matches RELEASE"
	@grep -q "<DisableDebug>$(CONFIG_DISABLE_DEBUG)</DisableDebug>" $(Enclave_Config_Gen)
	@echo "GATE 6: LVI mitigation in the artifact (MITIGATION-CVE-2020-0551=$(MITIGATION-CVE-2020-0551))"
	@n=$$(objdump -d $(Enclave_Name) | awk '$$NF=="lfence"' | wc -l); echo "  lfence instructions: $$n (minimum $(LFENCE_MIN))"; echo "$$n" > build/lfence-count.txt; \
	if [ "$$n" -lt "$(LFENCE_MIN)" ]; then echo "FATAL: mitigation requested but the artifact carries only $$n lfence"; exit 1; fi
	@if [ -f "$(Signed_Enclave_Name)" ] && [ "$(CEREMONY)" = "1" ]; then \
	    echo "GATE 7: MRSIGNER of $(Signed_Enclave_Name) is the pinned ceremony key (ceremony/mrsigner.txt)"; \
	    $(SGX_ENCLAVE_SIGNER) dump -enclave $(Signed_Enclave_Name) -dumpfile build/sigstruct.dump >/dev/null 2>&1; \
	    got=$$(grep -A2 'mrsigner->value' build/sigstruct.dump | tail -2 | tr -d ' \n' | sed 's/0x//g'); want=$$(tr -d ' \n' < ceremony/mrsigner.txt); \
	    echo "  MRSIGNER $$got"; if [ "$$got" != "$$want" ]; then echo "FATAL: MRSIGNER $$got != pinned $$want"; exit 1; fi; \
	fi
	@echo "GATES: all passed"

clean:
	@rm -f .config_* $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_C_Objects) Enclave/Enclave_t.* App/Enclave_u.* $(Bridge_Lib) $(Enclave_Config_Gen)

######## Two-step (ceremony) signing — REQ-r6 §3 ########
# gendata on the build host, the operator signs offline, catsig here. The private key never
# touches this machine; the public key is pinned in ceremony/ceremony_pub.pem.
gendata: $(Enclave_Name) $(Enclave_Config_Gen)
	@$(SGX_ENCLAVE_SIGNER) gendata -enclave $(Enclave_Name) -config $(Enclave_Config_Gen) -out build/enclave_hash.hex
	@echo "GENDATA => build/enclave_hash.hex ($$(stat -c %s build/enclave_hash.hex) bytes): sign it on the operator machine"
catsig: $(Enclave_Name) $(Enclave_Config_Gen)
	@test -s build/signature.hex || { echo "FATAL: build/signature.hex missing — run scripts/ceremony-sign.sh on the operator machine"; exit 1; }
	@$(SGX_ENCLAVE_SIGNER) catsig -enclave $(Enclave_Name) -config $(Enclave_Config_Gen) -key ceremony/ceremony_pub.pem -sig build/signature.hex -unsigned build/enclave_hash.hex -out $(Signed_Enclave_Name)
	@echo "CATSIG => $(Signed_Enclave_Name) (ceremony key)"
.PHONY: gendata catsig
