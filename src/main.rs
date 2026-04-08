// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use blake2::{Blake2b128, Blake2b256, Digest};
use clap::Parser;
use hex::encode_to_slice;
use hex_literal::hex;
use rand_pcg::{Lcg128CmDxsm64, Mcg128Xsl64, rand_core::SeedableRng};
use std::{
    io::{Error as IoError, Write, stdout},
    mem::MaybeUninit,
};

// ===========================================================================
// Types
// ===========================================================================

/// Supported random number generators
enum Generator {
    Pcg64Dxsm(Lcg128CmDxsm64),
    Pcg64Mcg(Mcg128Xsl64),
}

/// The aligned byte buffer (64 bytes)
#[repr(align(64))]
struct AlignedBuffer<const CAPACITY: usize>(pub [u8; CAPACITY]);

impl<const CAPACITY: usize> AlignedBuffer<CAPACITY> {
    const fn default() -> Self {
        Self([0u8; CAPACITY])
    }

    fn uninit() -> Self {
        let array: MaybeUninit<[u8; CAPACITY]> = MaybeUninit::uninit();
        Self(unsafe { array.assume_init() })
    }
}

// ===========================================================================
// Utilities
// ===========================================================================

/// First 32 bytes of the fractional part of ***e*** (Euler's number)
const SALT_1: [u8; 32usize] = hex!("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");

/// First 16 bytes of the fractional part of ***&pi;*** (pi)
const SALT_2: [u8; 16usize] = hex!("243F6A8885A308D313198A2E03707344");

#[inline(always)]
fn derive_seed_256(input: u128) -> [u8; 32usize] {
    Blake2b256::default().chain_update(input.to_be_bytes()).chain_update(SALT_1).finalize().into()
}

#[inline(always)]
fn derive_seed_128(input: u128) -> [u8; 16usize] {
    Blake2b128::default().chain_update(input.to_be_bytes()).chain_update(SALT_2).finalize().into()
}

#[inline(always)]
fn get_os_entropy<const N: usize>() -> [u8; N] {
    let mut seed_value = [0u8; N];
    getrandom::fill(&mut seed_value).expect("Failed to generate seed!");
    seed_value
}

#[inline(always)]
fn remaining<const LIMIT: usize>(total_bytes: u64, bytes_written: u64) -> usize {
    total_bytes.saturating_sub(bytes_written).min(LIMIT as u64) as usize
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
    const CHUNK_SIZE: usize = 16usize * 1024usize;
    let mut hex_buffer: AlignedBuffer<{ 2usize * CHUNK_SIZE }> = AlignedBuffer::uninit();

    for chunk in data.chunks(CHUNK_SIZE) {
        let hex_length = chunk.len().checked_mul(2usize).unwrap();
        encode_to_slice(chunk, &mut hex_buffer.0[..hex_length]).unwrap();
        output.write_all(&hex_buffer.0[..hex_length])?;
    }

    Ok(())
}

// ===========================================================================
// MT Generator
// ===========================================================================

mod mt {
    use super::{AlignedBuffer, remaining};
    use parking_lot::{Condvar, Mutex};
    use rand_pcg::rand_core::Rng;
    use std::{
        io::{Error as IoError, StdoutLock, Write},
        sync::atomic::{AtomicBool, Ordering},
        thread,
    };

    const BUFFER_SIZE: usize = 64usize * 1024usize; // 64 KB
    const NUM_BUFFERS: usize = 16usize;

    #[repr(align(64))]
    struct ThreadBuffer {
        used: bool,
        data: AlignedBuffer<BUFFER_SIZE>,
    }

    impl ThreadBuffer {
        const fn default() -> Self {
            Self { used: false, data: AlignedBuffer::default() }
        }
    }

    static RUNNING_FLAG: AtomicBool = AtomicBool::new(true);
    static BUFFER: [Mutex<ThreadBuffer>; NUM_BUFFERS] = [const { Mutex::new(ThreadBuffer::default()) }; NUM_BUFFERS];
    static COND_FREE: [Condvar; NUM_BUFFERS] = [const { Condvar::new() }; NUM_BUFFERS];
    static COND_USED: [Condvar; NUM_BUFFERS] = [const { Condvar::new() }; NUM_BUFFERS];

    pub fn generate<F>(mut generator: impl Rng + Send + 'static, mut output: StdoutLock, write_fn: F, count: Option<u64>)
    where
        F: Fn(&mut dyn Write, &[u8]) -> Result<(), IoError>,
    {
        let mut bytes_written = 0u64;

        let handle = thread::spawn(move || {
            while RUNNING_FLAG.load(Ordering::Relaxed) {
                for i in 0usize..NUM_BUFFERS {
                    let mut buffer = BUFFER[i].lock();
                    while buffer.used {
                        COND_FREE[i].wait(&mut buffer);
                    }
                    generator.fill_bytes(&mut buffer.data.0);
                    buffer.used = true;
                    COND_USED[i].notify_one();
                }
            }
        });

        'out_loop: loop {
            for i in 0usize..NUM_BUFFERS {
                let chunk_size = count.map(|total_bytes| remaining::<BUFFER_SIZE>(total_bytes, bytes_written)).unwrap_or(BUFFER_SIZE);
                if chunk_size == 0usize {
                    break 'out_loop;
                }
                let mut buffer = BUFFER[i].lock();
                while !buffer.used {
                    COND_USED[i].wait(&mut buffer);
                }
                if write_fn(&mut output, &buffer.data.0[..chunk_size]).is_err() {
                    break 'out_loop;
                }
                bytes_written += chunk_size as u64;
                buffer.used = false;
                COND_FREE[i].notify_one();
            }
        }

        RUNNING_FLAG.store(false, Ordering::Relaxed);

        for i in 0usize..NUM_BUFFERS {
            let mut buffer = BUFFER[i].lock();
            buffer.used = false;
            COND_FREE[i].notify_one();
        }

        handle.join().unwrap();
    }
}

// ===========================================================================
// ST Generator
// ===========================================================================

mod st {
    use super::{AlignedBuffer, remaining};
    use rand_pcg::rand_core::Rng;
    use std::io::{Error as IoError, StdoutLock, Write};

    const BUFFER_SIZE: usize = 32usize * 1024usize; // 32 KB

    pub fn generate<F>(mut generator: impl Rng, mut output: StdoutLock, write_fn: F, count: Option<u64>)
    where
        F: Fn(&mut dyn Write, &[u8]) -> Result<(), IoError>,
    {
        let mut bytes_written = 0u64;
        let mut buffer: AlignedBuffer<BUFFER_SIZE> = AlignedBuffer::default();

        if let Some(total_bytes) = count {
            while bytes_written < total_bytes {
                let chunk_size = remaining::<BUFFER_SIZE>(total_bytes, bytes_written);
                generator.fill_bytes(&mut buffer.0[..chunk_size]);
                if write_fn(&mut output, &buffer.0[..chunk_size]).is_err() {
                    break;
                }
                bytes_written += chunk_size as u64;
            }
        } else {
            loop {
                generator.fill_bytes(&mut buffer.0);
                if write_fn(&mut output, &buffer.0).is_err() {
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
            Some(input) => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(derive_seed_256(input))),
            None => Generator::Pcg64Dxsm(Lcg128CmDxsm64::from_seed(get_os_entropy())),
        }
    } else {
        match args.seed {
            Some(input) => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(derive_seed_128(input))),
            None => Generator::Pcg64Mcg(Mcg128Xsl64::from_seed(get_os_entropy())),
        }
    };

    let output = stdout().lock();

    #[allow(clippy::collapsible_else_if)]
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
