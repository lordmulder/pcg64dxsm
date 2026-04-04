// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use hex_literal::hex;
use sha3::{Digest, Sha3_512};
use std::{
    ffi::OsStr,
    fmt::UpperHex,
    io::Read,
    process::{Command, Stdio},
};

const BUFFER_SIZE: usize = 1024usize * 1024usize; //  1 MB
const OUTPUT_SIZE: u64 = 16u64 * 1024u64 * 1024u64 * 1024u64; // 16 GB

const ENTROPY_SIZE: u64 = 16u64 * 1024u64 * 1024u64; // 16 MB
const ENTROPY_ITER: usize = 1024usize;

// ===========================================================================
// Utilities
// ===========================================================================

struct Hex<'a>(&'a [u8]);

impl<'a> UpperHex for Hex<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for value in self.0 {
            write!(f, "{:02X}", value)?;
        }
        Ok(())
    }
}

fn run_process<const N: usize>(output_size: u64, args: [&OsStr; N]) -> [u8; 64usize] {
    let mut child_process = Command::new(env!("CARGO_BIN_EXE_pcg64dxsm")).args(args).stdout(Stdio::piped()).spawn().expect("Failed to spawn process!");
    let mut stdout = child_process.stdout.take().expect("No stdout!");
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut length = 0u64;
    let mut hasher = Sha3_512::default();

    while length < output_size {
        let remaining = (output_size - length).min(BUFFER_SIZE as u64) as usize;
        let read_size = stdout.read(&mut buffer[..remaining]).expect("Failed to read data!");
        assert!(read_size > 0usize);
        hasher.update(&buffer[..read_size]);
        length = length.checked_add(read_size as u64).unwrap();
    }

    assert_eq!(length, output_size);
    _ = child_process.kill();
    child_process.wait().expect("Failed to wait for child process!");

    hasher.finalize().into()
}

fn _digest_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        panic!("Digest values do *not* have the same length!");
    }

    let mut mask = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        mask |= x ^ y;
    }

    mask == 0u8
}

macro_rules! digest_eq {
    ($a:ident, $b:ident) => {
        println!("Expected: {:X}", Hex(&$a));
        println!("Computed: {:X}", Hex(&$b));
        assert!(_digest_eq(&$a, &$b));
    };
}

macro_rules! digest_ne {
    ($a:ident, $b:ident) => {
        assert!(!_digest_eq(&$a, &$b));
    };
}

// ===========================================================================
// Test Cases
// ===========================================================================

// Test vectors
const PCG64DXSM_0: [u8; 64usize] =
    hex!("D3BDDE89041CDEA70C28AD83334F4C73FD95980FD91B5D9FD3320EBC29AC9357792471C54DDAC32F841AC907C196D4E42EBF54BD135398760787F45F77FFE082");
const PCG64DXSM_1: [u8; 64usize] =
    hex!("B3A788C66AB91A6D729F49717CB95FA0717398E78933BA55CB46E005151207531268A2310E1EF2D6F59A23104BAD364A82A3D5D18526280828B5BF1CB71C855B");
const PCG64DXSM_2: [u8; 64usize] =
    hex!("51AE561D2532578124B4751B19436C67D00CD491561FCA7F234E8058733D38352D55EA964B374722459B9D2D6C2F944DAA9BDED486D26C6DBD772628A58737EF");
const PCG64FAST_0: [u8; 64usize] =
    hex!("9D34B2FF11B28339D659856EC8EC1CB5C85D5CAF7A8D0FCB130F267FBE07880791CD935B20D2C65F61A377A9EFC418A6FF40788E7BC99CCA77F88C7DE21C3729");
const PCG64FAST_1: [u8; 64usize] =
    hex!("C2224E68FEC72E825C710175CA5E07FF333BC5A3817F2FBB80D1B4C8578CBEDFB4FABDFE591D05FA8B478351EF6C647925850B7D8CAC55B93BF5A190FE9C0208");
const PCG64FAST_2: [u8; 64usize] =
    hex!("923DB754E71BFA403ED8CACB5C05622DC0169F3166CB8A9831A5C60454D35D3C58B87042AB7352FF742FE3D43EE26D64C50D7F436F55765E5CA2DC161ECE2F72");

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// pcg64_dxsm
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#[test]
fn test_pcg64dxsm_0() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_0);
}

#[test]
fn test_pcg64dxsm_1() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("1")]);
    digest_eq!(digest, PCG64DXSM_1);
}

#[test]
fn test_pcg64dxsm_2() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("2")]);
    digest_eq!(digest, PCG64DXSM_2);
}

#[test]
fn test_pcg64dxsm_threaded_0() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--thread"), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_0);
}

#[test]
fn test_pcg64dxsm_threaded_1() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--thread"), OsStr::new("1")]);
    digest_eq!(digest, PCG64DXSM_1);
}

#[test]
fn test_pcg64dxsm_threaded_2() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--thread"), OsStr::new("2")]);
    digest_eq!(digest, PCG64DXSM_2);
}

#[test]
fn test_pcg64dxsm_entropy() {
    let mut digest_all: Vec<[u8; 64usize]> = Vec::with_capacity(ENTROPY_ITER);
    for _i in 0usize..ENTROPY_ITER {
        digest_all.push(run_process(ENTROPY_SIZE, []));
    }

    for (i, &digest_1) in digest_all.iter().enumerate() {
        for (j, &digest_2) in digest_all.iter().enumerate() {
            if i != j {
                digest_ne!(digest_1, digest_2);
            }
        }
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// pcg64_fast
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#[test]
fn test_pcg64fast_0() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_0);
}

#[test]
fn test_pcg64fast_1() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("1")]);
    digest_eq!(digest, PCG64FAST_1);
}

#[test]
fn test_pcg64fast_2() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("2")]);
    digest_eq!(digest, PCG64FAST_2);
}

#[test]
fn test_pcg64fast_threaded_0() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_0);
}

#[test]
fn test_pcg64fast_threaded_1() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("1")]);
    digest_eq!(digest, PCG64FAST_1);
}

#[test]
fn test_pcg64fast_threaded_2() {
    let digest = run_process(OUTPUT_SIZE, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("2")]);
    digest_eq!(digest, PCG64FAST_2);
}

#[test]
fn test_pcg64fast_entropy() {
    let mut digest_all: Vec<[u8; 64usize]> = Vec::with_capacity(ENTROPY_ITER);
    for _i in 0usize..ENTROPY_ITER {
        digest_all.push(run_process(ENTROPY_SIZE, [OsStr::new("--fast")]));
    }

    for (i, &digest_1) in digest_all.iter().enumerate() {
        for (j, &digest_2) in digest_all.iter().enumerate() {
            if i != j {
                digest_ne!(digest_1, digest_2);
            }
        }
    }
}
