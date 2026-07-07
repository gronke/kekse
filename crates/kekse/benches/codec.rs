//! Criterion micro-benchmarks for the codec hot paths: request-header parse,
//! `Set-Cookie` parse, serialization, cookie-dates, and jar queries.
//!
//! Run as `cargo bench -p kekse --bench codec` — always by target name, so
//! criterion's CLI flags never reach the library's libtest harness. Compare
//! commits with `-- --save-baseline <name>` and `-- --baseline <name>`.

mod common;

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use kekse::{Cookie, CookieJar, SetCookie, ValueEncoding, parse_pairs};
use rfc_6265::date::{format_imf_fixdate, parse_cookie_date, parse_imf_fixdate};

use common::{
    DIRTY, ESCAPED, IMF, MEDIUM, QUOTED, RFC850, SET_COOKIE_EXPIRES, SET_COOKIE_FULL,
    SET_COOKIE_MIN, SMALL, WHEN, large_header, query_jar, query_jar_header, set_cookie_expires,
    set_cookie_full,
};

fn cookie_parse(c: &mut Criterion) {
    let large = large_header();
    let mut group = c.benchmark_group("cookie_parse");

    for (id, header) in [
        ("jar_lenient/small", SMALL),
        ("jar_lenient/medium", MEDIUM),
        ("jar_lenient/escaped", ESCAPED),
        ("jar_lenient/quoted", QUOTED),
    ] {
        group.throughput(Throughput::Bytes(header.len() as u64));
        group.bench_function(id, |b| b.iter(|| CookieJar::parse(black_box(header))));
    }

    group.throughput(Throughput::Bytes(large.len() as u64));
    group.bench_function("jar_lenient/large", |b| {
        b.iter(|| CookieJar::parse(black_box(&large)))
    });

    group.throughput(Throughput::Bytes(MEDIUM.len() as u64));
    group.bench_function("jar_strict/medium", |b| {
        b.iter(|| CookieJar::parse_strict(black_box(MEDIUM)))
    });

    group.throughput(Throughput::Bytes(DIRTY.len() as u64));
    group.bench_function("jar_reported/dirty", |b| {
        b.iter(|| CookieJar::parse_reported(black_box(DIRTY)))
    });

    // The streaming cost alone, without collecting into a jar — the delta to
    // `jar_lenient/medium` is what jar collection costs.
    group.throughput(Throughput::Bytes(MEDIUM.len() as u64));
    group.bench_function("pairs_drain/medium", |b| {
        b.iter(|| {
            parse_pairs(black_box(MEDIUM)).for_each(|pair| {
                black_box(&pair);
            });
        })
    });

    group.finish();
}

fn set_cookie_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_cookie_parse");

    for (id, header) in [
        ("lenient/min", SET_COOKIE_MIN),
        ("lenient/full", SET_COOKIE_FULL),
        ("lenient/expires", SET_COOKIE_EXPIRES),
    ] {
        group.throughput(Throughput::Bytes(header.len() as u64));
        group.bench_function(id, |b| b.iter(|| SetCookie::parse(black_box(header))));
    }

    group.throughput(Throughput::Bytes(SET_COOKIE_FULL.len() as u64));
    group.bench_function("strict/full", |b| {
        b.iter(|| SetCookie::parse_strict(black_box(SET_COOKIE_FULL)))
    });

    group.finish();
}

fn serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    let min = SetCookie::new("n", "v");
    group.bench_function("to_set_cookie/min", |b| {
        b.iter(|| black_box(&min).to_set_cookie())
    });

    let full = set_cookie_full();
    group.bench_function("to_set_cookie/full", |b| {
        b.iter(|| black_box(&full).to_set_cookie())
    });

    let expires = set_cookie_expires();
    group.bench_function("to_set_cookie/expires", |b| {
        b.iter(|| black_box(&expires).to_set_cookie())
    });

    group.bench_function("header_value/full", |b| {
        b.iter(|| http::HeaderValue::try_from(black_box(&full)))
    });

    let jar = CookieJar::parse(MEDIUM);
    group.bench_function("jar_to_header_string/medium", |b| {
        b.iter(|| black_box(&jar).to_header_string(ValueEncoding::Percent))
    });

    let clean = Cookie::new("pref", "deadbeef");
    group.bench_function("to_pair/clean", |b| {
        b.iter(|| black_box(&clean).to_pair(ValueEncoding::Percent))
    });

    let escaped = Cookie::new("pref", "hello world");
    group.bench_function("to_pair/escaped", |b| {
        b.iter(|| black_box(&escaped).to_pair(ValueEncoding::Percent))
    });

    group.finish();
}

fn date(c: &mut Criterion) {
    let mut group = c.benchmark_group("date");

    group.bench_function("parse_cookie_date/imf", |b| {
        b.iter(|| parse_cookie_date(black_box(IMF)))
    });
    group.bench_function("parse_cookie_date/rfc850", |b| {
        b.iter(|| parse_cookie_date(black_box(RFC850)))
    });
    group.bench_function("parse_imf_fixdate/imf", |b| {
        b.iter(|| parse_imf_fixdate(black_box(IMF)))
    });
    group.bench_function("format_imf_fixdate", |b| {
        b.iter(|| format_imf_fixdate(black_box(WHEN)))
    });

    group.finish();
}

fn jar_query(c: &mut Criterion) {
    let header = query_jar_header();
    let jar = query_jar(&header);
    let mut group = c.benchmark_group("jar_query");

    group.bench_function("get/first", |b| {
        b.iter(|| black_box(&jar).get(black_box("k0")))
    });
    group.bench_function("get/last", |b| {
        b.iter(|| black_box(&jar).get(black_box("k16")))
    });
    group.bench_function("get/miss", |b| {
        b.iter(|| black_box(&jar).get(black_box("absent")))
    });
    group.bench_function("get_all_count/dup", |b| {
        b.iter(|| black_box(&jar).get_all(black_box("dup")).count())
    });

    group.finish();
}

criterion_group!(
    benches,
    cookie_parse,
    set_cookie_parse,
    serialize,
    date,
    jar_query
);
criterion_main!(benches);
