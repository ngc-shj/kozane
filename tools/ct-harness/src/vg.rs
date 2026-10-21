//! Valgrind client requests (M4 plan C9) and the one declassification
//! point. check-pins P15 allows the client-request instruction sequence
//! here and nowhere else.
//!
//! The sequence is aarch64 `VALGRIND_DO_CLIENT_REQUEST_EXPR` from
//! valgrind 3.24's `valgrind.h`: the default result in x3, the address of
//! a six-word argument block in x4, the magic preamble, then
//! `orr x10, x10, x10`; valgrind leaves the result in x3. Natively the
//! preamble is a no-op (four rotations of x12 summing to 128) and x3 keeps
//! the default.

#![allow(unsafe_code)]

use core::arch::asm;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::policy::{Kind, Site};

const RUNNING_ON_VALGRIND: u64 = 0x1001;
/// `VG_USERREQ_TOOL_BASE('M', 'C')` (memcheck.h).
const MC: u64 = ((b'M' as u64) << 24) | ((b'C' as u64) << 16);
const MAKE_MEM_UNDEFINED: u64 = MC + 1;
const MAKE_MEM_DEFINED: u64 = MC + 2;
const GET_VBITS: u64 = MC + 8;

#[inline(never)]
fn request(default: u64, req: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let args: [u64; 6] = [req, a1, a2, a3, 0, 0];
    let mut res = default;
    // SAFETY: natively the sequence only rotates x12 back to itself and
    // ors x10 with itself. Under valgrind it is a client request: memcheck
    // reads the argument block and, for the requests issued here, reads or
    // updates its shadow state for the caller's live buffer `a1..a1+a3`
    // (GET_VBITS also writes the caller's `a2..a2+a3`). No memory of the
    // program changes except GET_VBITS's output, which the asm declares by
    // not being `nomem`.
    unsafe {
        asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            inout("x3") res,
            in("x4") args.as_ptr(),
            options(nostack),
        );
    }
    res
}

/// `RUNNING_ON_VALGRIND`.
pub fn running_on_valgrind() -> bool {
    request(0, RUNNING_ON_VALGRIND, 0, 0, 0) != 0
}

/// `VALGRIND_MAKE_MEM_UNDEFINED`: `buf` becomes secret.
pub fn mark_secret(buf: &mut [u8]) {
    request(
        0,
        MAKE_MEM_UNDEFINED,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );
}

/// `VALGRIND_GET_VBITS`, as a count: how many bytes of `buf` memcheck
/// holds fully undefined (all eight V bits set). `None` if the request
/// failed (not running, or `buf` not addressable).
pub fn undefined_bytes(buf: &[u8]) -> Option<usize> {
    let mut vbits = vec![0u8; buf.len()];
    let r = request(
        0,
        GET_VBITS,
        buf.as_ptr() as u64,
        vbits.as_mut_ptr() as u64,
        buf.len() as u64,
    );
    (r == 1).then(|| vbits.iter().filter(|&&v| v == 0xff).count())
}

static POLICY: OnceLock<Vec<Site>> = OnceLock::new();
static USED: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// Installs the declassification policy (`policy/ct-declassify.toml`).
pub fn set_policy(sites: Vec<Site>) {
    assert!(POLICY.set(sites).is_ok(), "policy set twice");
}

/// The sites declassified so far, with their call counts.
pub fn used_sites() -> BTreeMap<String, u64> {
    USED.lock().expect("ledger").clone()
}

/// The only declassification: `VALGRIND_MAKE_MEM_DEFINED` on `buf`, at the
/// policy site `id`. An unlisted id, or a buffer that is not exactly the
/// site's width, ends the run before anything is declassified (exit 5).
/// `buf` is `&mut` so that the caller rereads it from memory afterwards.
pub fn declassify(id: &str, buf: &mut [u8]) {
    let sites = POLICY.get().map(Vec::as_slice).unwrap_or(&[]);
    let Some(site) = sites.iter().find(|s| s.id == id) else {
        refuse(&format!("{id}: not in the policy"));
    };
    if buf.len() != site.width {
        refuse(&format!(
            "{id}: {} bytes, the site's width is {}",
            buf.len(),
            site.width
        ));
    }
    request(
        0,
        MAKE_MEM_DEFINED,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );
    if site.kind == Kind::Predicate && buf[0] > 1 {
        refuse(&format!("{id}: predicate value {} is not 0 or 1", buf[0]));
    }
    *USED
        .lock()
        .expect("ledger")
        .entry(id.to_owned())
        .or_insert(0) += 1;
}

fn refuse(why: &str) -> ! {
    println!("CT-DECLASSIFY-REFUSED {why}");
    std::process::exit(5);
}
