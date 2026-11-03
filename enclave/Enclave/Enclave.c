/* tee-signer enclave shell: edger8r glue only. The decision code is Rust (librcore.a). */
#include <stddef.h>
#include <stdint.h>
#include "Enclave_t.h"

int rcore_call(uint32_t op, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap, size_t* out_len);

int ecall_call(uint32_t op, const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap, size_t* out_len)
{
    return rcore_call(op, in, in_len, out, out_cap, out_len);
}
