//! [`LogicalCookie`] — the honest cookie a scenario is "about" — and
//! [`KeksbruchRecipe`], which renders it two ways: a clean `baseline()` **through
//! kekse**, and a corrupted `render()` built **directly as bytes** (kekse's
//! encoders refuse to emit `;`/CR/LF/NUL, so keksbruch hand-crafts them).

use std::borrow::Cow;

use kekse::{Cookie, CookieAttributes, SetCookie, ValueEncoding};

use crate::taxonomy::{Direction, Keksbruch};

/// The intended cookie before any corruption — a name, a decoded value, the wire
/// encoding its baseline renders under, and (for a response) its attributes.
#[derive(Clone, Debug)]
pub struct LogicalCookie<'a> {
    pub name: &'a str,
    pub value: Cow<'a, str>,
    pub encoding: ValueEncoding,
    pub attributes: CookieAttributes<'a>,
}

impl<'a> LogicalCookie<'a> {
    /// A bare cookie — name and value, default encoding, no attributes.
    pub fn new(name: &'a str, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name,
            value: value.into(),
            encoding: ValueEncoding::default(),
            attributes: CookieAttributes::default(),
        }
    }

    /// The **clean** wire, rendered *through kekse* — the honest form keksbruch
    /// then corrupts. Reuses `Cookie::to_request_pair` /
    /// `SetCookie::to_set_cookie`, so it proves kekse can emit the baseline.
    pub fn baseline(&self, direction: Direction) -> String {
        let kernel = Cookie::new(self.name, self.value.clone()).with_encoding(self.encoding);
        match direction {
            Direction::Request => kernel.to_request_pair(),
            Direction::Response => {
                SetCookie::from_parts(kernel, self.attributes.clone()).to_set_cookie()
            }
        }
    }
}

/// A logical cookie plus the corruption to apply, in a given direction.
#[derive(Clone, Debug)]
pub struct KeksbruchRecipe<'a> {
    pub base: LogicalCookie<'a>,
    pub keksbruch: Keksbruch,
    pub direction: Direction,
}

impl<'a> KeksbruchRecipe<'a> {
    /// Pair a base, a `Keksbruch`, and a direction.
    pub fn new(base: LogicalCookie<'a>, keksbruch: Keksbruch, direction: Direction) -> Self {
        Self {
            base,
            keksbruch,
            direction,
        }
    }

    /// Build the **corrupted** wire directly as bytes. Returns `Vec<u8>` because a
    /// `Keksbruch` may inject CR/LF/NUL or a raw non-UTF-8 byte that no `&str` could
    /// hold — those are exactly the shapes a parser must survive.
    pub fn render(&self) -> Vec<u8> {
        let n = self.base.name;
        match (&self.keksbruch, self.direction) {
            (Keksbruch::SurroundingWhitespace, _) => format!("  {n}  =  v  ").into_bytes(),
            (Keksbruch::InternalWhitespace, _) => format!("{n}=a b").into_bytes(),

            (Keksbruch::NulInValue, Direction::Request) => splice(n, 0, b"; m=ok"),
            (Keksbruch::NulInValue, Direction::Response) => splice(n, 0, b""),
            (Keksbruch::CrlfInValue, Direction::Request) => {
                format!("{n}=a\r\nb; m=ok").into_bytes()
            }
            (Keksbruch::CrlfInValue, Direction::Response) => format!("{n}=a\r\nb").into_bytes(),
            (Keksbruch::ControlInValue(byte), Direction::Request) => splice(n, *byte, b"; m=ok"),
            (Keksbruch::ControlInValue(byte), Direction::Response) => splice(n, *byte, b""),

            (Keksbruch::UnbalancedQuote, _) => format!("{n}=\"v; m=ok").into_bytes(),
            (Keksbruch::InteriorQuote, _) => format!("{n}=a\"b; m=ok").into_bytes(),

            (Keksbruch::TruncatedPercent, _) => format!("{n}=%4; m=ok").into_bytes(),
            (Keksbruch::InvalidUtf8Percent, _) => format!("{n}=%FF; m=ok").into_bytes(),
            (Keksbruch::RawInvalidUtf8Byte, _) => splice(n, 0xFF, b""),

            (Keksbruch::SemicolonInValue, _) => format!("{n}=a;evil=1").into_bytes(),
            (Keksbruch::EmptySegments, _) => format!("{n}=v;;;m=w").into_bytes(),
            (Keksbruch::NoEquals, _) => format!("flag; {n}=v").into_bytes(),
            (Keksbruch::ExtraEquals, _) => format!("{n}=a=b").into_bytes(),

            (Keksbruch::DuplicateName, _) => format!("{n}=1; {n}=2; {n}=3").into_bytes(),
            (Keksbruch::CaseVariantDuplicate, _) => {
                format!("{n}=lo; {}=hi", n.to_uppercase()).into_bytes()
            }

            (Keksbruch::EmptyName, _) => "=v; m=ok".to_string().into_bytes(),
            (Keksbruch::EmptyValue, _) => format!("{n}=; m=ok").into_bytes(),

            (Keksbruch::RawNonAsciiValue, _) => format!("{n}=café; m=ok").into_bytes(),
            (Keksbruch::NonAsciiName, _) => "naïve=v; m=ok".to_string().into_bytes(),

            (Keksbruch::NulInName, _) => {
                let mut w = n.as_bytes().to_vec();
                w.push(0);
                w.extend_from_slice(b"x=v; m=ok");
                w
            }
            (Keksbruch::NulBetweenCookies, _) => {
                let mut w = b"a=1; ".to_vec();
                w.push(0);
                w.extend_from_slice(b"b=2; c=3");
                w
            }
            (Keksbruch::TabAround, _) => format!("\t{n}\t=\tv\t; m=ok").into_bytes(),
            (Keksbruch::RawEmojiValue, _) => format!("{n}=🤖; m=ok").into_bytes(),
            (Keksbruch::PercentEmojiValue, _) => format!("{n}=%F0%9F%A4%96; m=ok").into_bytes(),

            (Keksbruch::HugeValue(k), _) => format!("{n}={}", "x".repeat(*k)).into_bytes(),
            (Keksbruch::ManyPairs(k), _) => {
                let mut s: String = (0..*k).map(|i| format!("k{i}=v{i}; ")).collect();
                s.push_str("target=found");
                s.into_bytes()
            }
            (Keksbruch::ControlJunkRun(k), _) => {
                let mut w = b"a=1; j=".to_vec();
                w.resize(w.len() + *k, 1u8);
                w.extend_from_slice(b"; b=2");
                w
            }

            (Keksbruch::UnknownAttribute(attr), Direction::Response) => {
                format!("{}; {attr}=High", self.base.baseline(Direction::Response)).into_bytes()
            }
            (Keksbruch::BadMaxAge(val), Direction::Response) => {
                format!("{}; Max-Age={val}", self.base.baseline(Direction::Response)).into_bytes()
            }
            (Keksbruch::GarbageSameSite(val), Direction::Response) => format!(
                "{}; SameSite={val}",
                self.base.baseline(Direction::Response)
            )
            .into_bytes(),
            (Keksbruch::ValuedFlag(flag), Direction::Response) => {
                format!("{}; {flag}=1", self.base.baseline(Direction::Response)).into_bytes()
            }
            (Keksbruch::DuplicateAttribute(attr), Direction::Response) => format!(
                "{}; {attr}=/a; {attr}=/b",
                self.base.baseline(Direction::Response)
            )
            .into_bytes(),
            (Keksbruch::NulInAttrName, Direction::Response) => {
                let mut w = format!("{}; Pa", self.base.baseline(Direction::Response)).into_bytes();
                w.push(0);
                w.extend_from_slice(b"th=/");
                w
            }
            (Keksbruch::NulInAttrValue, Direction::Response) => {
                let mut w =
                    format!("{}; Path=/a", self.base.baseline(Direction::Response)).into_bytes();
                w.push(0);
                w.push(b'b');
                w
            }

            // The Response-only attribute Keksbruch variants are never paired with Request in
            // the corpus; fall back to the honest baseline so the match is total.
            (
                Keksbruch::UnknownAttribute(_)
                | Keksbruch::BadMaxAge(_)
                | Keksbruch::GarbageSameSite(_)
                | Keksbruch::ValuedFlag(_)
                | Keksbruch::DuplicateAttribute(_)
                | Keksbruch::NulInAttrName
                | Keksbruch::NulInAttrValue,
                Direction::Request,
            ) => self.base.baseline(Direction::Request).into_bytes(),
        }
    }

    /// The wire as a `&str`-able `String` when it is valid UTF-8 — the bridge to
    /// kekse's `&str` parsers. `None` when a `Keksbruch` injected a raw non-UTF-8
    /// byte: those wires can never reach a `&str` parser (the `http` layer rejects
    /// the header bytes upstream — the boundary kekse relies on).
    pub fn render_str(&self) -> Option<String> {
        String::from_utf8(self.render()).ok()
    }
}

/// `n=a<byte>b` then `tail` — a value with one spliced raw byte, as bytes.
fn splice(name: &str, byte: u8, tail: &[u8]) -> Vec<u8> {
    let mut w = format!("{name}=a").into_bytes();
    w.push(byte);
    w.push(b'b');
    w.extend_from_slice(tail);
    w
}
