// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use clap::Parser;
use hex_literal::hex;
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

/// First 32 bytes of the fractional part of ***e*** (Euler's number)
///
/// This is an arbitrary but unsuspicious (nothing-up-my-sleeve) choice for a sufficiantly "random" value that we can use as a salt.
///
/// Replace with a custom "salt" value as needed!
const SALT_VALUE: [u8; 32usize] = hex!("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");

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
    seed: Option<u128>,
}

fn main() {
    let args = Args::parse();

    let generator = if !args.fast {
        match args.seed {
            Some(input) => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(derive_seed(input, b"Lcg128CmDxsm64"))),
            None => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(get_os_entropy())),
        }
    } else {
        match args.seed {
            Some(input) => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(derive_seed(input, b"Mcg128Xsl64"))),
            None => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(get_os_entropy())),
        }
    };

    let output = stdout().lock();

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
