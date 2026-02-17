use criterion::{criterion_group, criterion_main, Criterion};
use std::path::Path;

use rustdefend::scanner::Scanner;

fn bench_scan_single_file(c: &mut Criterion) {
    // Scan a single detector implementation file
    let file_path = Path::new("src/detectors/solana/missing_signer.rs");
    if !file_path.exists() {
        return;
    }

    c.bench_function("scan_single_file", |b| {
        b.iter(|| {
            let scanner = Scanner::new();
            let _ = scanner.scan(file_path);
        })
    });
}

fn bench_scan_directory(c: &mut Criterion) {
    // Scan the solana detectors directory
    let dir_path = Path::new("src/detectors/solana");
    if !dir_path.exists() {
        return;
    }

    c.bench_function("scan_solana_detectors", |b| {
        b.iter(|| {
            let scanner = Scanner::new();
            let _ = scanner.scan(dir_path);
        })
    });
}

fn bench_scan_fixtures(c: &mut Criterion) {
    // Scan the test fixtures
    let dir_path = Path::new("test-fixtures");
    if !dir_path.exists() {
        return;
    }

    c.bench_function("scan_test_fixtures", |b| {
        b.iter(|| {
            let scanner = Scanner::new();
            let _ = scanner.scan(dir_path);
        })
    });
}

criterion_group!(
    benches,
    bench_scan_single_file,
    bench_scan_directory,
    bench_scan_fixtures
);
criterion_main!(benches);
