// SPDX-License-Identifier: 0BSD
// Lcg128CmDxsm64 (PCG64DXSM)
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use clap::Parser;
use hkdf::Hkdf;
use parking_lot::{Condvar, Mutex};
use rand_pcg::{
    Lcg128CmDxsm64, Mcg128Xsl64,
    rand_core::{Rng, SeedableRng},
};
use sha3::Sha3_256;
use std::{
    io::{Write, stdout},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

/// Supported random number generators
enum Generator {
    Pcg64Dxsm(Lcg128CmDxsm64),
    Pcg64Mcg(Mcg128Xsl64),
}

// ===========================================================================
// MT Generator
// ===========================================================================

const BUFF_SIZE: usize = 8192usize;
const NUM_BUFFERS: usize = 16usize;

static RUNNING: AtomicBool = AtomicBool::new(true);

static BUFFER: [Mutex<(bool, [u8; BUFF_SIZE])>; NUM_BUFFERS] = [
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
    Mutex::new((false, [0u8; _])),
];

static COND_FREE: [Condvar; NUM_BUFFERS] = [
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
];

static COND_USED: [Condvar; NUM_BUFFERS] = [
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
    Condvar::new(),
];

fn generate_mt(mut generator: impl Rng + Send + 'static, mut output: impl Write) {
    let handle = thread::spawn(move || {
        while RUNNING.load(Ordering::Relaxed) {
            for i in 0usize..NUM_BUFFERS {
                let mut buffer = BUFFER[i].lock();
                while buffer.0 {
                    COND_FREE[i].wait(&mut buffer);
                }
                generator.fill_bytes(&mut buffer.1);
                buffer.0 = true;
                COND_USED[i].notify_one();
            }
        }
    });

    'main_loop: loop {
        for i in 0usize..NUM_BUFFERS {
            let mut buffer = BUFFER[i].lock();
            while !buffer.0 {
                COND_USED[i].wait(&mut buffer);
            }
            if output.write_all(&buffer.1).is_err() {
                break 'main_loop;
            }
            buffer.0 = false;
            COND_FREE[i].notify_one();
        }
    }

    RUNNING.store(false, Ordering::Relaxed);

    for i in 0usize..NUM_BUFFERS {
        let mut buffer = BUFFER[i].lock();
        buffer.0 = false;
        COND_FREE[i].notify_one();
    }

    handle.join().unwrap();
}

// ===========================================================================
// ST Generator
// ===========================================================================

fn generate_st(mut generator: impl Rng, mut output: impl Write) {
    let mut buffer = [0u8; BUFF_SIZE];
    loop {
        generator.fill_bytes(&mut buffer);
        if output.write_all(&buffer).is_err() {
            break;
        }
    }
}

// ===========================================================================
// Utilities
// ===========================================================================

const SALT_VALUE: &[u8; 32usize] = b"\x27\x92\xAD\x8B\x34\x21\xFD\xFD\x73\x09\x87\xE6\x91\x45\x76\xD0\xD0\xC6\x80\x2A\x4E\x79\x77\xB2\x5D\x93\xA3\x2A\x61\xF3\x37\x2C";

fn derive_seed<const N: usize>(input: u128, label: &[u8]) -> [u8; N] {
    let mut seed_value = [0u8; _];
    let hkdf = Hkdf::<Sha3_256>::new(Some(&SALT_VALUE[..]), &input.to_be_bytes());
    hkdf.expand(label, &mut seed_value).unwrap();
    seed_value
}

fn get_os_entropy<const N: usize>() -> [u8; N] {
    let mut seed_value = [0u8; _];
    getrandom::fill(&mut seed_value).expect("Failed to generate seed!");
    seed_value
}

// ===========================================================================
// Main
// ===========================================================================

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Enable multi-threaded random number generation
    #[arg(short, long)]
    thread: bool,

    /// Use faster algorithm, with slightly worse statistical properties
    #[arg(short, long)]
    fast: bool,

    /// User-defined seed value; if not specified, seed from OS entropy source
    #[arg(conflicts_with = "entropy")]
    seed: Option<u128>,
}

fn main() {
    let args = Args::parse();
    let output = stdout().lock();

    let generator = if !args.fast {
        match args.seed {
            Some(seed_value) => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(derive_seed(
                seed_value,
                b"Lcg128CmDxsm64",
            ))),
            None => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(get_os_entropy())),
        }
    } else {
        match args.seed {
            Some(seed_value) => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(derive_seed(
                seed_value,
                b"Mcg128Xsl64",
            ))),
            None => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(get_os_entropy())),
        }
    };

    if args.thread {
        match generator {
            Generator::Pcg64Dxsm(pcg64dxsm) => generate_mt(pcg64dxsm, output),
            Generator::Pcg64Mcg(pcg64mcg) => generate_mt(pcg64mcg, output),
        }
    } else {
        match generator {
            Generator::Pcg64Dxsm(pcg64dxsm) => generate_st(pcg64dxsm, output),
            Generator::Pcg64Mcg(pcg64mcg) => generate_st(pcg64mcg, output),
        }
    }
}
