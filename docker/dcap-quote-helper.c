/* dcap-quote-helper — untrusted host side. One process, the whole DCAP flow:
 *   stdout <- 512 bytes: the quoting enclave's target_info
 *   stdin  -> 432 bytes: the application enclave's report bound to that target
 *   stdout <- u32 LE quote size, then the quote
 * Why a separate process (learned on DCsv3 by the sibling projects): libsgx_dcap_ql loads its own
 * enclaves and cannot share a process with the loaded application enclave, and the attestation key
 * initialised in QE3 is lost if target_info and get_quote happen in different processes.
 * az-dcap-client logs to stdout unless told otherwise, which would corrupt the stream.
 * Build: gcc -O2 -o dcap-quote-helper dcap-quote-helper.c -ldl */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned int (*pfn_pol)(unsigned int);
typedef unsigned int (*pfn_ti)(void *);
typedef unsigned int (*pfn_qs)(uint32_t *);
typedef unsigned int (*pfn_gq)(const void *, uint32_t, uint8_t *);
static int read_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return 0;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += (size_t)r; n -= (size_t)r;
    }
    return 1;
}
int main(void) {
    setenv("AZDCAP_DEBUG_LOG_LEVEL", "FATAL", 0);
    void *lib = dlopen("libsgx_dcap_ql.so.1", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    pfn_pol fpol = (pfn_pol)dlsym(lib, "sgx_qe_set_enclave_load_policy");
    pfn_ti fti = (pfn_ti)dlsym(lib, "sgx_qe_get_target_info");
    pfn_qs fqs = (pfn_qs)dlsym(lib, "sgx_qe_get_quote_size");
    pfn_gq fgq = (pfn_gq)dlsym(lib, "sgx_qe_get_quote");
    if (!fti || !fqs || !fgq) { fprintf(stderr, "dlsym failed\n"); return 1; }
    if (fpol) fpol(1); /* SGX_QL_PERSISTENT: keep QE3 loaded across the three calls */
    uint8_t ti[512] = {0};
    unsigned int r = fti(ti);
    if (r != 0) { fprintf(stderr, "sgx_qe_get_target_info: 0x%x\n", r); return 1; }
    if (fwrite(ti, 1, sizeof ti, stdout) != sizeof ti) return 1;
    fflush(stdout);
    uint8_t report[432] = {0};
    if (read_all(0, report, sizeof report) != 1) { fprintf(stderr, "report read failed\n"); return 1; }
    uint32_t qsize = 0;
    r = fqs(&qsize);
    if (r != 0 || qsize == 0 || qsize > (1u << 20)) { fprintf(stderr, "sgx_qe_get_quote_size: 0x%x\n", r); return 1; }
    uint8_t *quote = calloc(1, qsize);
    if (!quote) return 1;
    r = fgq(report, qsize, quote);
    if (r != 0) { fprintf(stderr, "sgx_qe_get_quote: 0x%x\n", r); return 1; }
    uint8_t len[4] = { qsize & 0xff, (qsize >> 8) & 0xff, (qsize >> 16) & 0xff, (qsize >> 24) & 0xff };
    if (fwrite(len, 1, 4, stdout) != 4 || fwrite(quote, 1, qsize, stdout) != qsize) return 1;
    fflush(stdout);
    return 0;
}
