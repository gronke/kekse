//! Shared wire-level segmentation for the two readers — the byte-side counterpart of the
//! `grammar` predicates. One home for "split at the first `=`, trim OWS around the name, gate the
//! name as a token", so the request reader (`jar`'s `split_pairs`) and the response reader
//! ([`SetCookie::parse`](crate::SetCookie::parse)) cannot drift — and one home for the fail-soft
//! trace both emit when a name flunks the gate.
//!
//! Byte-level on purpose: an HTTP header value may legally carry obs-text (`>= 0x80`) that is not
//! UTF-8, and fail-soft parsing must be able to skip such a pair *individually* instead of forcing
//! the caller to drop the whole header at a `to_str()` boundary. Names stay `&str` in the output —
//! a cookie-name is an RFC 7230 token, tokens are ASCII, so the view is free once the gate passed.

use rfc_6265::grammar::{is_cookie_name_bytes, is_ws};

/// Trim `SP`/`HTAB` from both ends — the byte form of `trim_matches(is_ws_char)`. Deliberately
/// NOT `trim_ascii`, which would also strip CR/LF/FF/VT: RFC 6265 OWS is `SP`/`HTAB` only, and a
/// control byte must *survive* into the token/octet gates to be rejected there, not be trimmed
/// into acceptance.
pub(crate) fn trim_ws(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes
        && is_ws(*first)
    {
        bytes = rest;
    }
    while let [rest @ .., last] = bytes
        && is_ws(*last)
    {
        bytes = rest;
    }
    bytes
}

/// Split one `name=value` unit at its **first** `=` (so `=` survives inside values), trim OWS
/// around the name, and require a non-empty cookie-name token. Returns the name as `&str` — free
/// after the token gate, since tchars are ASCII — and the raw, untrimmed value bytes. `None`
/// (debug-logged under `tracing`) when there is no `=` at all or the name is empty / not a token.
pub(crate) fn split_checked_pair(segment: &[u8]) -> Option<(&str, &[u8])> {
    // `slice::split_once` is still unstable; `position` + index split is the stable spelling.
    let eq = segment.iter().position(|&b| b == b'=')?;
    let (raw_name, raw_value) = (&segment[..eq], &segment[eq + 1..]);
    let name = trim_ws(raw_name);
    if !is_cookie_name_bytes(name) {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            name = %String::from_utf8_lossy(name).escape_debug(),
            "ignoring a cookie pair with an empty or non-token name"
        );
        return None;
    }
    // Infallible after the token gate (tchar ⊂ ASCII); `.ok()?` keeps the no-panic
    // promise without reaching for `unsafe`.
    Some((std::str::from_utf8(name).ok()?, raw_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::is_ws_char;

    #[test]
    fn trim_ws_matches_the_str_form_and_only_touches_sp_htab() {
        for s in ["", " ", "\t \t", " a ", "a", "\ta\t", " a b ", "  = "] {
            assert_eq!(
                trim_ws(s.as_bytes()),
                s.trim_matches(is_ws_char).as_bytes(),
                "{s:?}"
            );
        }
        // CR/LF/FF/VT are NOT whitespace here — they must survive into the grammar gates.
        for s in ["\ra\r", "\na\n", "\x0ca\x0c", "\x0ba\x0b"] {
            assert_eq!(trim_ws(s.as_bytes()), s.as_bytes(), "{s:?}");
        }
    }

    #[test]
    fn split_checked_pair_takes_the_first_equals_and_gates_the_name() {
        // `=` in the value survives; the name is OWS-trimmed.
        assert_eq!(split_checked_pair(b" n =v=w"), Some(("n", &b"v=w"[..])));
        // The value is handed over raw — untrimmed, unvalidated.
        assert_eq!(split_checked_pair(b"n= v "), Some(("n", &b" v "[..])));
        // No `=`, empty name, whitespace-only name, non-token name: all refused.
        for bad in &[
            &b"novalue"[..],
            b"",
            b"=v",
            b" \t=v",
            b"a b=v",
            b"a;b=v",
            b"caf\xc3\xa9=v",
            b"a\xffb=v",
        ] {
            assert_eq!(split_checked_pair(bad), None, "{bad:?}");
        }
    }
}
