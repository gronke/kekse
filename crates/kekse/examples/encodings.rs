//! The cookie-value codec: how each `ValueEncoding` escapes a value for the wire.
//!
//! Run with: `cargo run -p kekse --example encodings`

use kekse::{Cookie, ValueEncoding, encode_value, parse_pairs};

fn main() {
    // A value an RFC 6265 cookie cannot carry bare: it has a space and a `;`.
    let value = "a b;c";
    println!("value: {value:?}\n");

    // The three managed encodings render it differently, but each is lossless.
    for enc in [
        ValueEncoding::Auto,
        ValueEncoding::Percent,
        ValueEncoding::Quoted,
    ] {
        let pair = Cookie::new("x", value).with_encoding(enc).to_request_pair();
        // Pad the (derived-`Debug`) label by hand: `Debug` ignores width specs.
        println!("  {:<9}{pair}", format!("{enc:?}:"));
    }

    // `encode_value` is the same codec without the `Cookie` wrapper.
    println!(
        "\nencode_value(Percent): {}",
        encode_value(value, ValueEncoding::Percent)
    );

    // `parse_pairs` is the inverse of every managed encoding — round-trip back.
    let wire = Cookie::new("x", value)
        .with_encoding(ValueEncoding::Percent)
        .to_request_pair();
    let (name, decoded) = parse_pairs(&wire).next().expect("one pair on the wire");
    println!("round-trip {wire:?} -> ({name:?}, {decoded:?})");
    assert_eq!(name, "x");
    assert_eq!(&*decoded, value);

    // `Raw` is the escape hatch: emitted verbatim, the caller owns correctness.
    let raw = Cookie::new("y", "already-octets")
        .with_encoding(ValueEncoding::Raw)
        .to_request_pair();
    println!("Raw (verbatim): {raw}");
}
