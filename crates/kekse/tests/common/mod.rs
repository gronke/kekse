//! Shared fixtures for the per-RFC compliance suite. Each test file that needs
//! them does `mod common;`. Not every file uses every helper, so the module-wide
//! `allow(dead_code)` keeps the unused-in-this-binary items quiet.
#![allow(dead_code)]

/// Wire-dangerous and otherwise awkward values, reused across encode/parse tests.
pub const HOSTILE: &[&str] = &[
    "a;b",
    "a b",
    "a\tb",
    "a,b",
    "a\"b",
    "a\\b",
    "a=b",
    "café",
    "🦀🍪",
    "100%",
    "%41",
    "a\r\nSet-Cookie: evil=1",
    "\u{0}\u{1}\u{7f}",
    "",
];

/// Every ASCII byte `0x00..=0x7F` paired with its single-character `String`.
/// Bytes `>= 0x80` cannot form a one-byte `&str`, so non-ASCII is covered by
/// explicit fixtures instead.
pub fn ascii_singletons() -> impl Iterator<Item = (u8, String)> {
    (0u8..=0x7f).map(|b| (b, (b as char).to_string()))
}
