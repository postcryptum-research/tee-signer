# enclave/ — the SGX enclave

`rcore/` is the Rust FFI crate (the only `unsafe` in the TCB; `docs/ENCLAVE.md`); `Enclave/` is
the edger8r glue, the EDL (one ecall, no ocalls), the signed config and the linker script;
`App/` holds the generated untrusted bridge, archived as `libenclave_u.a` for `host/signerd`.

Builds **on the SGX box** (`make` with the SDK at `/opt/intel/sgxsdk`); nothing here builds in a
laptop session. `make RELEASE=1` pins `DisableDebug=1`, drops every test feature and asserts the
gates (no `cpuid`, no test symbols, no TEXTREL, config matches). The T1 box can only *launch*
debug enclaves, so a release build there is a build check, not a runnable one.

Host-side logic tests without SGX: `cd rcore && cargo test --features nosgx,test-init` (the SDK
calls are stubbed, the seal is a tagged plaintext container; never an enclave build).
