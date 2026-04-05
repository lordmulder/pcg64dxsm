// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use clap::Parser;
use hex::encode_to_slice;
use hex_literal::hex;
use hkdf::Hkdf;
use rand_pcg::{Lcg128CmDxsm64, Mcg128Xsl64, rand_core::SeedableRng};
use sha3::Sha3_256;
use std::{
    io::{Error as IoError, Write, stdout},
    mem::MaybeUninit,
};

/// Supported random number generators
enum Generator {
    Pcg64Dxsm(Lcg128CmDxsm64),
    Pcg64Mcg(Mcg128Xsl64),
}

/// Buffer size
const BUFF_SIZE: usize = 8192usize;

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

#[inline(always)]
fn remaining(total_bytes: u64, bytes_written: u64) -> usize {
    total_bytes.saturating_sub(bytes_written).min(BUFF_SIZE as u64) as usize
}

// ===========================================================================
// Output Functions
// ===========================================================================

#[inline(always)]
fn write_raw(output: &mut dyn Write, data: &[u8]) -> Result<(), IoError> {
    output.write_all(data)
}

#[inline(always)]
fn write_hex(output: &mut dyn Write, data: &[u8]) -> Result<(), IoError> {
    let mut array: MaybeUninit<[u8; 2usize * BUFF_SIZE]> = MaybeUninit::uninit();
    let hex_buffer = unsafe { array.assume_init_mut() };
    let hex_length = data.len().checked_mul(2usize).unwrap();
    encode_to_slice(data, &mut hex_buffer[..hex_length]).unwrap();
    output.write_all(&hex_buffer[..hex_length])
}

// ===========================================================================
// MT Generator
// ===========================================================================

mod mt {
    use super::{BUFF_SIZE, remaining};
    use parking_lot::{Condvar, Mutex};
    use rand_pcg::rand_core::Rng;
    use std::{
        io::{Error as IoError, StdoutLock, Write},
        sync::atomic::{AtomicBool, Ordering},
        thread,
    };

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

    pub fn generate<F>(mut generator: impl Rng + Send + 'static, mut output: StdoutLock, write_fn: F, count: Option<u64>)
    where
        F: Fn(&mut dyn Write, &[u8]) -> Result<(), IoError>,
    {
        let mut bytes_written = 0u64;

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

        'out_loop: loop {
            for i in 0usize..NUM_BUFFERS {
                let chunk_size = count.map(|total_bytes| remaining(total_bytes, bytes_written)).unwrap_or(BUFF_SIZE);
                if chunk_size == 0usize {
                    break 'out_loop;
                }
                let mut buffer = BUFFER[i].lock();
                while !buffer.0 {
                    COND_USED[i].wait(&mut buffer);
                }
                if write_fn(&mut output, &buffer.1[..chunk_size]).is_err() {
                    break 'out_loop;
                }
                bytes_written += chunk_size as u64;
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
}

// ===========================================================================
// ST Generator
// ===========================================================================

mod st {
    use super::{BUFF_SIZE, remaining};
    use rand_pcg::rand_core::Rng;
    use std::io::{Error as IoError, StdoutLock, Write};

    pub fn generate<F>(mut generator: impl Rng, mut output: StdoutLock, write_fn: F, count: Option<u64>)
    where
        F: Fn(&mut dyn Write, &[u8]) -> Result<(), IoError>,
    {
        let mut bytes_written = 0u64;
        let mut buffer = [0u8; BUFF_SIZE];

        if let Some(total_bytes) = count {
            while bytes_written < total_bytes {
                let chunk_size = remaining(total_bytes, bytes_written);
                generator.fill_bytes(&mut buffer[..chunk_size]);
                if write_fn(&mut output, &buffer[..chunk_size]).is_err() {
                    break;
                }
                bytes_written += chunk_size as u64;
            }
        } else {
            loop {
                generator.fill_bytes(&mut buffer);
                if write_fn(&mut output, &buffer).is_err() {
                    break;
                }
            }
        }
    }
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

    /// Use a faster algorithm (pcg64_fast) with slightly worse properties
    #[arg(short, long)]
    fast: bool,

    /// Limit output the the specified number of bytes
    #[arg(short, long)]
    count: Option<u64>,

    /// Output random data as hex-encoded string; default is "raw" bytes
    #[arg(short = 'H', long)]
    hex: bool,

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
        if !args.hex {
            match generator {
                Generator::Pcg64Dxsm(pcg64dxsm) => mt::generate(pcg64dxsm, output, write_raw, args.count),
                Generator::Pcg64Mcg(pcg64mcg) => mt::generate(pcg64mcg, output, write_raw, args.count),
            }
        } else {
            match generator {
                Generator::Pcg64Dxsm(pcg64dxsm) => mt::generate(pcg64dxsm, output, write_hex, args.count),
                Generator::Pcg64Mcg(pcg64mcg) => mt::generate(pcg64mcg, output, write_hex, args.count),
            }
        }
    } else {
        if !args.hex {
            match generator {
                Generator::Pcg64Dxsm(pcg64dxsm) => st::generate(pcg64dxsm, output, write_raw, args.count),
                Generator::Pcg64Mcg(pcg64mcg) => st::generate(pcg64mcg, output, write_raw, args.count),
            }
        } else {
            match generator {
                Generator::Pcg64Dxsm(pcg64dxsm) => st::generate(pcg64dxsm, output, write_hex, args.count),
                Generator::Pcg64Mcg(pcg64mcg) => st::generate(pcg64mcg, output, write_hex, args.count),
            }
        }
    }
}
