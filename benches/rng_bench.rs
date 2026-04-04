// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::{
    ffi::OsStr,
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};

const BUFFER_SIZE: usize = 8192usize;
const OUTPUT_SIZE: u64 = 16u64 * 1024u64 * 1024u64 * 1024u64; // 16 GB

// ===========================================================================
// Utilities
// ===========================================================================

fn run_process<const N: usize>(args: [&OsStr; N]) {
    let mut child_process = Command::new(env!("CARGO_BIN_EXE_pcg64dxsm")).args(args).stdout(Stdio::piped()).spawn().expect("Failed to spawn process!");
    let mut stdout = child_process.stdout.take().expect("No stdout!");
    let mut length = 0u64;
    let mut buffer = [0u8; BUFFER_SIZE];

    while length < OUTPUT_SIZE {
        let remaining = (OUTPUT_SIZE - length).min(BUFFER_SIZE as u64) as usize;
        let read_size = stdout.read(&mut buffer[..remaining]).expect("Failed to read data!");
        assert!(read_size > 0usize);
        length = length.checked_add(read_size as u64).unwrap();
    }

    assert_eq!(length, OUTPUT_SIZE);
    _ = child_process.kill();
    child_process.wait().expect("Failed to wait for child process!");
}

// ===========================================================================
// Benchmarks
// ===========================================================================

fn prng_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("rng_bench");
    group.sample_size(13);
    group.measurement_time(Duration::from_secs(600));
    group.warm_up_time(Duration::from_secs(180));
    group.throughput(Throughput::Bytes(OUTPUT_SIZE));
    group.bench_function("pcg64dxsm-ST", |b| b.iter(|| run_process([])));
    group.bench_function("pcg64dxsm-MT", |b| b.iter(|| run_process([OsStr::new("--thread")])));
    group.bench_function("pcg64fast-ST", |b| b.iter(|| run_process([OsStr::new("--fast")])));
    group.bench_function("pcg64fast-MT", |b| b.iter(|| run_process([OsStr::new("--fast"), OsStr::new("--thread")])));
    group.finish();
}

criterion_group!(benches, prng_bench);
criterion_main!(benches);
