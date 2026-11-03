//! Global allocator over the enclave C runtime (`libsgx_tstdc`): `malloc` / `free` / `memalign`.
//! Under `nosgx` the host's libc provides the same symbols.

use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn memalign(align: usize, size: usize) -> *mut u8;
    fn free(p: *mut u8);
}

struct Tstdc;

unsafe impl GlobalAlloc for Tstdc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= 16 {
            malloc(layout.size().max(1))
        } else {
            memalign(layout.align(), layout.size().max(1))
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, _layout: Layout) {
        free(p)
    }
}

#[global_allocator]
static GLOBAL: Tstdc = Tstdc;
