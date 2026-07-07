//! Deterministic allocation counts for the codec hot paths — the timing-free
//! companion to the `codec` bench, over the same shared inputs. Run as
//! `cargo bench -p kekse --bench allocs`; each scenario prints how many heap
//! allocations and how many bytes one operation requests.
//!
//! The kekse library forbids `unsafe`; this standalone bench binary hosts the
//! one `unsafe impl` a counting `GlobalAlloc` requires, delegating every call
//! straight to the `System` allocator.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use kekse::{Cookie, CookieJar, SetCookie, ValueEncoding};
use rfc_6265::date::format_imf_fixdate;

use common::{
    DIRTY, ESCAPED, MEDIUM, SET_COOKIE_EXPIRES, SET_COOKIE_FULL, SMALL, WHEN, large_header,
    set_cookie_expires, set_cookie_full,
};

/// The `System` allocator with every requested allocation counted.
/// Deallocations are deliberately uncounted: the scenarios report how much a
/// single operation asks of the allocator, not its live footprint.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Count a grow like a fresh request of the new size; the default
        // `GlobalAlloc::realloc` would route through `alloc` + `dealloc` and
        // hide that `System` can often grow in place.
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Run `op` once and return `(allocations, bytes)` it requested.
fn measure<T>(op: impl FnOnce() -> T) -> (usize, usize) {
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let bytes = BYTES.load(Ordering::Relaxed);
    let out = op();
    let measured = (
        ALLOCATIONS.load(Ordering::Relaxed) - allocations,
        BYTES.load(Ordering::Relaxed) - bytes,
    );
    drop(black_box(out));
    measured
}

fn main() {
    // Inputs are built before any measurement brackets them.
    let large = large_header();
    let jar_medium = CookieJar::parse(MEDIUM);
    let set_cookie_min = SetCookie::new("n", "v");
    let full = set_cookie_full();
    let expires = set_cookie_expires();
    let clean_pair = Cookie::new("pref", "deadbeef");

    let scenarios: Vec<(&str, (usize, usize))> = vec![
        ("jar_parse/small", measure(|| CookieJar::parse(SMALL))),
        ("jar_parse/medium", measure(|| CookieJar::parse(MEDIUM))),
        ("jar_parse/large", measure(|| CookieJar::parse(&large))),
        ("jar_parse/escaped", measure(|| CookieJar::parse(ESCAPED))),
        (
            "jar_reported/dirty",
            measure(|| CookieJar::parse_reported(DIRTY)),
        ),
        (
            "set_cookie_parse/full",
            measure(|| SetCookie::parse(SET_COOKIE_FULL)),
        ),
        (
            "set_cookie_parse/expires",
            measure(|| SetCookie::parse(SET_COOKIE_EXPIRES)),
        ),
        (
            "to_pair/clean",
            measure(|| clean_pair.to_pair(ValueEncoding::Percent)),
        ),
        (
            "jar_to_header_string/medium",
            measure(|| jar_medium.to_header_string(ValueEncoding::Percent)),
        ),
        (
            "to_set_cookie/min",
            measure(|| set_cookie_min.to_set_cookie()),
        ),
        ("to_set_cookie/full", measure(|| full.to_set_cookie())),
        ("to_set_cookie/expires", measure(|| expires.to_set_cookie())),
        (
            "header_value/full",
            measure(|| http::HeaderValue::try_from(&full)),
        ),
        ("format_imf_fixdate", measure(|| format_imf_fixdate(WHEN))),
    ];

    println!("{:34} {:>7} {:>9}", "scenario", "allocs", "bytes");
    for (name, (allocations, bytes)) in scenarios {
        println!("{name:34} {allocations:>7} {bytes:>9}");
    }
}
