//! Parse-issue reporting: what a parse refused, as data.
//!
//! Every reader returns this form — there is no silent variant. A refused
//! piece is skipped, never aborting the parse, and handed back as an issue,
//! so the caller chooses the severity: log the [`Reported::issues`] and keep
//! the value (fail-soft, observed), treat any issue as fatal (fail-hard — a
//! `400 Bad Request` for a request header the client had no business
//! sending), or discard the report ([`Reported::into_value`]).
//!
//! [`PairIssue`] is one refused request-`Cookie:` pair; [`Reported`] carries a
//! parsed value together with everything the parse refused, in wire order.

use std::fmt;

/// Render untrusted wire bytes for a log line or error message: UTF-8-lossy,
/// then `escape_debug`, so every control byte (CR/LF, NUL, …) comes out as a
/// printable escape — an issue can never split the log line or response it is
/// rendered into, no matter what the wire carried.
pub(crate) fn lossy_escaped(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}

/// One request `Cookie:` pair a reader refused, carrying the offending wire
/// slice — borrowed from the header, never allocated.
///
/// Yielded in place by [`parse_pairs`](crate::parse_pairs) (and its strict /
/// bytes twins) and collected by [`CookieJar::parse`](crate::CookieJar::parse).
/// An empty or whitespace-only `;`-segment (a stray or trailing `;`) is
/// structural noise, not an issue — the same treatment the `Set-Cookie`
/// attribute loop gives it.
///
/// The payloads are byte slices because the readers are byte-level (a header
/// may legally carry obs-text that is not UTF-8); through the `&str` entry
/// points every slice is split at ASCII delimiters and therefore valid UTF-8.
/// The [`Display`](fmt::Display) form escapes them (`escape_debug`), so a
/// rendered issue never carries a raw control byte (CR/LF, NUL, …).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PairIssue<'a> {
    /// A non-empty segment with no `=` at all — a bare `garbage` token.
    #[non_exhaustive]
    MissingEquals {
        /// The raw, untrimmed segment.
        segment: &'a [u8],
    },
    /// The OWS-trimmed name is empty or not an RFC 7230 token.
    #[non_exhaustive]
    InvalidName {
        /// The OWS-trimmed name bytes that flunked the token gate.
        name: &'a [u8],
    },
    /// The name parsed, but the value carries a byte outside the accepted set
    /// (in strict mode that includes raw `SP`/`HTAB`) or percent-escapes that
    /// do not decode to UTF-8.
    #[non_exhaustive]
    InvalidValue {
        /// The cookie-name whose value was refused.
        name: &'a str,
        /// The raw, untrimmed value bytes.
        value: &'a [u8],
    },
}

impl fmt::Display for PairIssue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEquals { segment } => {
                write!(f, "cookie pair `{}` has no `=`", lossy_escaped(segment))
            }
            Self::InvalidName { name } => {
                write!(
                    f,
                    "cookie name `{}` is empty or not a token",
                    lossy_escaped(name)
                )
            }
            Self::InvalidValue { name, value } => {
                write!(
                    f,
                    "cookie `{name}` value `{}` carries a byte outside the accepted set \
                     or percent-escapes that are not valid UTF-8",
                    lossy_escaped(value)
                )
            }
        }
    }
}

impl std::error::Error for PairIssue<'_> {}

/// A parse result carrying everything the parse refused.
///
/// `issues` is empty exactly when the input was fully well-formed, so
/// fail-hard is [`is_clean`](Reported::is_clean) / [`into_result`](Reported::into_result),
/// and fail-soft-but-observed is reading [`value`](Reported::value) and logging
/// [`issues`](Reported::issues). A clean parse never allocates for the report
/// (`Vec::new` holds no buffer).
///
/// Returned by [`CookieJar::parse`](crate::CookieJar::parse) (and its strict /
/// bytes twins) with `I` = [`PairIssue`], and by
/// [`SetCookie::try_parse`](crate::SetCookie::try_parse) with `I` =
/// [`SetCookieIssue`](crate::SetCookieIssue).
#[must_use = "the report carries both the parsed value and what was refused"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reported<T, I> {
    /// The parsed value — byte-identical to what the plain reader yields.
    pub value: T,
    /// Everything fail-soft dropped, in wire order.
    pub issues: Vec<I>,
}

impl<T, I> Reported<T, I> {
    /// Whether the parse recorded no issues — the fail-hard gate.
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }

    /// Split by cleanliness: `Ok(value)` iff no issues, else both the salvaged
    /// value and the issues. The `Result` view for callers who treat a dirty
    /// parse as an error but still want what survived.
    pub fn into_result(self) -> Result<T, (T, Vec<I>)> {
        if self.issues.is_empty() {
            Ok(self.value)
        } else {
            Err((self.value, self.issues))
        }
    }

    /// Discard the report — the bridge back to plain fail-soft.
    pub fn into_value(self) -> T {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_never_echoes_control_bytes() {
        let issues = [
            PairIssue::MissingEquals {
                segment: b"ga;rbage\r\n\x00",
            },
            PairIssue::InvalidName {
                name: b"a\xffb\r\n\x00;",
            },
            PairIssue::InvalidValue {
                name: "n",
                value: b"a\x01b;\r\n\x00\xe9",
            },
        ];
        for issue in issues {
            let rendered = issue.to_string();
            assert!(
                !rendered.bytes().any(|b| b.is_ascii_control()),
                "{rendered:?} carries a raw control byte"
            );
        }
    }

    #[test]
    fn into_result_splits_by_cleanliness() {
        let clean: Reported<u8, PairIssue<'_>> = Reported {
            value: 1,
            issues: Vec::new(),
        };
        assert!(clean.is_clean());
        assert_eq!(clean.into_result(), Ok(1));

        let dirty = Reported {
            value: 2,
            issues: vec![PairIssue::MissingEquals { segment: b"junk" }],
        };
        assert!(!dirty.is_clean());
        let (value, issues) = dirty.into_result().unwrap_err();
        assert_eq!(value, 2);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn into_value_discards_the_report() {
        let dirty = Reported {
            value: 3,
            issues: vec![PairIssue::MissingEquals { segment: b"junk" }],
        };
        assert_eq!(dirty.into_value(), 3);
    }
}
