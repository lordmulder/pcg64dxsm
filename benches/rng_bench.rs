// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use rolling_median::Median;
use std::{
    ffi::OsStr,
    io::Read,
    process::{Command, Stdio},
    time::Instant,
};

const BUFFER_SIZE: usize = 1024usize * 1024usize; //  1 MB
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

const REPEAT_COUNT: usize = 9usize;

fn run_bench<F: Fn()>(name: &str, bench_fn: F) -> f64 {
    println!("[{}]", name);
    let mut median: Median<f64> = Median::new();

    println!("Warm-up pass is running, please wait...");
    bench_fn();
    println!("Warm-up pass completed.");

    for i in 0usize..REPEAT_COUNT {
        let start_time = Instant::now();
        bench_fn();
        let elapsed = start_time.elapsed().as_secs_f64();
        println!("Run {} of {}: Execution completed after {:.2} second(s)", i + 1usize, REPEAT_COUNT, elapsed);
        median.push(elapsed).unwrap();
    }

    let median_time = median.get().unwrap();
    let throughput = (OUTPUT_SIZE as f64) / median_time / 1048576f64;
    println!("Finished -> Median execution time: {:.2} second(s) [{:.2} MiB/s]\n", median_time, throughput);
    throughput
}

fn main() {
    let pcg64dxsm_st = run_bench("pcg64dxsm-ST", || run_process([]));
    let pcg64dxsm_mt = run_bench("pcg64dxsm-MT", || run_process([OsStr::new("--thread")]));
    let pcg64fast_st = run_bench("pcg64fast-ST", || run_process([OsStr::new("--fast")]));
    let pcg64fast_mt = run_bench("pcg64fast-MT", || run_process([OsStr::new("--fast"), OsStr::new("--thread")]));

    println!("[Summary]");
    println!("pcg64dxsm-ST: {:.2} MiB/s", pcg64dxsm_st);
    println!("pcg64dxsm-MT: {:.2} MiB/s", pcg64dxsm_mt);
    println!("pcg64fast-ST: {:.2} MiB/s", pcg64fast_st);
    println!("pcg64fast-MT: {:.2} MiB/s", pcg64fast_mt);
}
