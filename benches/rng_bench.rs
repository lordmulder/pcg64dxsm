// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use clap::Parser;
use rolling_median::Median;
use std::{
    env,
    ffi::OsStr,
    io::Read,
    mem::MaybeUninit,
    process::{Command, Stdio},
    sync::LazyLock,
    time::Instant,
};

const BUFFER_SIZE: usize = 64usize * 1024usize; // 64 KB
const OUTPUT_SIZE: u64 = 16u64 * 1024u64 * 1024u64 * 1024u64; // 16 GB

// ===========================================================================
// Types
// ===========================================================================

/// The aligned byte buffer (64 bytes)
#[repr(align(64))]
struct AlignedBuffer<const CAPACITY: usize>(pub [u8; CAPACITY]);

impl<const CAPACITY: usize> AlignedBuffer<CAPACITY> {
    fn uninit() -> Self {
        let array: MaybeUninit<[u8; CAPACITY]> = MaybeUninit::uninit();
        Self(unsafe { array.assume_init() })
    }
}

// ===========================================================================
// Utilities
// ===========================================================================

static NULL_OUTPUT: LazyLock<bool> = LazyLock::new(|| {
    option_env!("BENCH_NULL_STDOUT")
        .map(str::trim_ascii)
        .filter(|str| !str::is_empty(str))
        .and_then(|str| str.parse::<usize>().ok())
        .map(|val| val > 0usize)
        .unwrap_or_default()
});

fn run_process<const N: usize>(args: [&OsStr; N]) {
    let mut child_process = Command::new(env!("CARGO_BIN_EXE_pcg64dxsm"))
        .args(args)
        .args([OsStr::new("--count"), OsStr::new(&OUTPUT_SIZE.to_string())])
        .stderr(Stdio::null())
        .stdout(if *NULL_OUTPUT { Stdio::null() } else { Stdio::piped() })
        .spawn()
        .expect("Failed to spawn the child process!");

    let mut buffer: AlignedBuffer<BUFFER_SIZE> = AlignedBuffer::uninit();
    let mut length = 0u64;

    if !*NULL_OUTPUT {
        let mut stdout = child_process.stdout.take().expect("No stdout stream!");
        loop {
            let read_len = stdout.read(&mut buffer.0).expect("Failed to read data from child process!");
            if read_len == 0usize {
                break;
            }
            length = length.saturating_add(read_len as u64);
        }
    }

    child_process.wait().expect("Failed to wait for child process!");

    if !*NULL_OUTPUT {
        assert_eq!(length, OUTPUT_SIZE);
    }
}

// ===========================================================================
// Benchmarks
// ===========================================================================

const REPEAT_COUNT: usize = 99usize;

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
        println!("Run {:2} of {:2}: Execution completed after {:.2} second(s)", i + 1usize, REPEAT_COUNT, elapsed);
        median.push(elapsed).unwrap();
    }

    let median_time = median.get().unwrap();
    let throughput = (OUTPUT_SIZE as f64) / median_time / 1048576f64;
    println!("Finished -> Median execution time: {:.2} second(s) [{:.3} MiB/s]\n", median_time, throughput);
    throughput
}

// ===========================================================================
// Main
// ===========================================================================

#[derive(Parser, Debug)]
struct Args {
    /// Run the single-threaded benchmarks only
    #[arg(long, conflicts_with = "mt")]
    st: bool,

    /// Run the multi-threaded benchmarks only
    #[arg(long, conflicts_with = "st")]
    mt: bool,

    /// Omnipresent argument (it will be ignored)
    #[arg(long)]
    _bench: bool,
}

macro_rules! run_if {
    ($flag:ident, $name:literal, $args:expr) => {
        if !$flag { f64::NAN } else { run_bench($name, || run_process($args)) }
    };
}

fn main() {
    let args = Args::parse();

    let run_st = args.st || !args.mt;
    let run_mt = args.mt || !args.st;

    let pcg64dxsm_st = run_if!(run_st, "pcg64dxsm-ST", []);
    let pcg64dxsm_mt = run_if!(run_mt, "pcg64dxsm-MT", [OsStr::new("--thread")]);
    let pcg64fast_st = run_if!(run_st, "pcg64fast-ST", [OsStr::new("--fast")]);
    let pcg64fast_mt = run_if!(run_mt, "pcg64fast-MT", [OsStr::new("--fast"), OsStr::new("--thread")]);

    println!("[Summary]");
    println!("pcg64dxsm-ST: {:7.2} MiB/s", pcg64dxsm_st);
    println!("pcg64dxsm-MT: {:7.2} MiB/s", pcg64dxsm_mt);
    println!("pcg64fast-ST: {:7.2} MiB/s", pcg64fast_st);
    println!("pcg64fast-MT: {:7.2} MiB/s", pcg64fast_mt);
}
