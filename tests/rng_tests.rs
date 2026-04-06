// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use hex::{FromHexError, decode_to_slice};
use hex_literal::hex;
use sha3::{Digest, Sha3_512};
use std::{
    ffi::OsStr,
    fmt::UpperHex,
    io::Read,
    process::{Command, Stdio},
};

const BUFFER_SIZE: usize = 512usize * 1024usize; //  512 KB
const OUTPUT_SIZE: u64 = 16u64 * 1024u64 * 1024u64 * 1024u64; // 16 GB

const ENTROPY_SIZE: u64 = 16u64 * 1024u64 * 1024u64; // 16 MB
const ENTROPY_ITER: usize = 1024usize;

// ===========================================================================
// Hex Support
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

// ===========================================================================
// Hex Decoder
// ===========================================================================

struct HexDecoder<const N: usize> {
    buffer: [u8; N],
    offset: usize,
}

impl<const N: usize> HexDecoder<N> {
    pub fn new() -> Self {
        const {
            assert!((N > 0usize) && (N & 1usize == 0usize));
        }
        Self { buffer: [0u8; N], offset: 0usize }
    }

    pub fn decode_inplace<'a>(&mut self, input: &'a mut [u8]) -> Result<&'a [u8], FromHexError> {
        let mut pos_get = 0usize;
        let mut pos_put = 0usize;

        while pos_get < input.len() {
            let copy_len = input.len().saturating_sub(pos_get).min(N.saturating_sub(self.offset));
            if copy_len > 0usize {
                self.buffer[self.offset..(self.offset + copy_len)].copy_from_slice(&input[pos_get..(pos_get + copy_len)]);
                pos_get = pos_get.checked_add(copy_len).unwrap();
                self.offset = self.offset.checked_add(copy_len).unwrap();
            }

            let decode_len = self.offset & (!1usize);
            if decode_len > 0usize {
                let output_len = decode_len / 2usize;
                decode_to_slice(&self.buffer[..decode_len], &mut input[pos_put..(pos_put + output_len)])?;
                if decode_len != self.offset {
                    assert_eq!(self.offset - decode_len, 1usize);
                    self.buffer[0usize] = self.buffer[self.offset - 1usize];
                }
                pos_put = pos_put.checked_add(output_len).unwrap();
                self.offset = self.offset.checked_sub(decode_len).unwrap();
            }
        }

        Ok(&input[..pos_put])
    }
}

// ===========================================================================
// Utilities
// ===========================================================================

fn run_process<const N: usize>(output_size: Option<u64>, hex_decode: bool, args: [&OsStr; N]) -> [u8; 64usize] {
    let mut child_process = Command::new(env!("CARGO_BIN_EXE_pcg64dxsm")).args(args).stdout(Stdio::piped()).spawn().expect("Failed to spawn process!");
    let mut stdout = child_process.stdout.take().expect("No stdout!");
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut hex_decoder = if hex_decode { Some(HexDecoder::<8192usize>::new()) } else { None };
    let mut length = 0u64;
    let mut hasher = Sha3_512::default();

    while output_size.is_none_or(|target_size| length < target_size) {
        let read_len = stdout.read(&mut buffer).expect("Failed to read data from child process!");
        if read_len == 0usize {
            break;
        }
        if let Some(decoder) = hex_decoder.as_mut() {
            let decoded = decoder.decode_inplace(&mut buffer[..read_len]).expect("Failed to decode hex-encoded input!");
            if !decoded.is_empty() {
                let chunk_size = output_size.map(|target_size| target_size.saturating_sub(length).min(decoded.len() as u64) as usize).unwrap_or(decoded.len());
                hasher.update(&decoded[..chunk_size]);
                length = length.checked_add(chunk_size as u64).unwrap();
            }
        } else {
            let chunk_size = output_size.map(|target_size| target_size.saturating_sub(length).min(read_len as u64) as usize).unwrap_or(read_len);
            hasher.update(&buffer[..chunk_size]);
            length = length.checked_add(chunk_size as u64).unwrap();
        }
    }

    drop(stdout);
    child_process.wait().expect("Failed to wait for child process!");

    if let Some(target_size) = output_size {
        assert_eq!(length, target_size);
    }

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
        println!("Computed: {:X}", Hex(&$a));
        println!("Expected: {:X}", Hex(&$b));
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
const PCG64DXSM_3: [u8; 64usize] =
    hex!("6234967E0BA08E045052C229C970447CA2FC1A535741EC09623B9791BDE7CB5C403817D191B60564DF40B6E21CAF75246A262C5196E787C482DC2BE467D5D27E");
const PCG64FAST_0: [u8; 64usize] =
    hex!("9D34B2FF11B28339D659856EC8EC1CB5C85D5CAF7A8D0FCB130F267FBE07880791CD935B20D2C65F61A377A9EFC418A6FF40788E7BC99CCA77F88C7DE21C3729");
const PCG64FAST_1: [u8; 64usize] =
    hex!("C2224E68FEC72E825C710175CA5E07FF333BC5A3817F2FBB80D1B4C8578CBEDFB4FABDFE591D05FA8B478351EF6C647925850B7D8CAC55B93BF5A190FE9C0208");
const PCG64FAST_2: [u8; 64usize] =
    hex!("923DB754E71BFA403ED8CACB5C05622DC0169F3166CB8A9831A5C60454D35D3C58B87042AB7352FF742FE3D43EE26D64C50D7F436F55765E5CA2DC161ECE2F72");
const PCG64FAST_3: [u8; 64usize] =
    hex!("017C0265677C70CC7035E9A42F2798515BEF1F09E0837055C4A8DCE9E43DE2D7FDAC13B481B2A34DB9899DB6B744A14C29AA34851FC7597B427D69CFCA61E77A");

/// Count to be sued for all `--count` test cases
const COUNT: usize = 4294967291usize;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// pcg64_dxsm
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#[test]
fn test_pcg64dxsm_0() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_0);
}

#[test]
fn test_pcg64dxsm_1() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("1")]);
    digest_eq!(digest, PCG64DXSM_1);
}

#[test]
fn test_pcg64dxsm_2() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("2")]);
    digest_eq!(digest, PCG64DXSM_2);
}

#[test]
fn test_pcg64dxsm_threaded_0() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--thread"), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_0);
}

#[test]
fn test_pcg64dxsm_threaded_1() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--thread"), OsStr::new("1")]);
    digest_eq!(digest, PCG64DXSM_1);
}

#[test]
fn test_pcg64dxsm_threaded_2() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--thread"), OsStr::new("2")]);
    digest_eq!(digest, PCG64DXSM_2);
}

#[test]
fn test_pcg64dxsm_entropy() {
    let mut digest_all: Vec<[u8; 64usize]> = Vec::with_capacity(ENTROPY_ITER);
    for _i in 0usize..ENTROPY_ITER {
        digest_all.push(run_process(Some(ENTROPY_SIZE), false, []));
    }

    for (i, &digest_1) in digest_all.iter().enumerate() {
        for (j, &digest_2) in digest_all.iter().enumerate() {
            if i != j {
                digest_ne!(digest_1, digest_2);
            }
        }
    }
}

#[test]
fn test_pcg64dxsm_count() {
    let digest = run_process(None, false, [OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_3);
}

#[test]
fn test_pcg64dxsm_count_threaded() {
    let digest = run_process(None, false, [OsStr::new("--thread"), OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_3);
}

#[test]
fn test_pcg64dxsm_hex_0() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--hex"), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_0);
}

#[test]
fn test_pcg64dxsm_hex_1() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--hex"), OsStr::new("1")]);
    digest_eq!(digest, PCG64DXSM_1);
}

#[test]
fn test_pcg64dxsm_hex_2() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--hex"), OsStr::new("2")]);
    digest_eq!(digest, PCG64DXSM_2);
}

#[test]
fn test_pcg64dxsm_count_hex() {
    let digest = run_process(None, true, [OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("--hex"), OsStr::new("0")]);
    digest_eq!(digest, PCG64DXSM_3);
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// pcg64_fast
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#[test]
fn test_pcg64fast_0() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_0);
}

#[test]
fn test_pcg64fast_1() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("1")]);
    digest_eq!(digest, PCG64FAST_1);
}

#[test]
fn test_pcg64fast_2() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("2")]);
    digest_eq!(digest, PCG64FAST_2);
}

#[test]
fn test_pcg64fast_threaded_0() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_0);
}

#[test]
fn test_pcg64fast_threaded_1() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("1")]);
    digest_eq!(digest, PCG64FAST_1);
}

#[test]
fn test_pcg64fast_threaded_2() {
    let digest = run_process(Some(OUTPUT_SIZE), false, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("2")]);
    digest_eq!(digest, PCG64FAST_2);
}

#[test]
fn test_pcg64fast_entropy() {
    let mut digest_all: Vec<[u8; 64usize]> = Vec::with_capacity(ENTROPY_ITER);
    for _i in 0usize..ENTROPY_ITER {
        digest_all.push(run_process(Some(ENTROPY_SIZE), false, [OsStr::new("--fast")]));
    }

    for (i, &digest_1) in digest_all.iter().enumerate() {
        for (j, &digest_2) in digest_all.iter().enumerate() {
            if i != j {
                digest_ne!(digest_1, digest_2);
            }
        }
    }
}

#[test]
fn test_pcg64fast_count() {
    let digest = run_process(None, false, [OsStr::new("--fast"), OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_3);
}

#[test]
fn test_pcg64fast_count_threaded() {
    let digest =
        run_process(None, false, [OsStr::new("--fast"), OsStr::new("--thread"), OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_3);
}

#[test]
fn test_pcg64fast_hex_0() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--fast"), OsStr::new("--hex"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_0);
}

#[test]
fn test_pcg64fast_hex_1() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--fast"), OsStr::new("--hex"), OsStr::new("1")]);
    digest_eq!(digest, PCG64FAST_1);
}

#[test]
fn test_pcg64fast_hex_2() {
    let digest = run_process(Some(OUTPUT_SIZE), true, [OsStr::new("--fast"), OsStr::new("--hex"), OsStr::new("2")]);
    digest_eq!(digest, PCG64FAST_2);
}

#[test]
fn test_pcg64fast_count_hex() {
    let digest = run_process(None, true, [OsStr::new("--fast"), OsStr::new("--count"), OsStr::new(&COUNT.to_string()), OsStr::new("--hex"), OsStr::new("0")]);
    digest_eq!(digest, PCG64FAST_3);
}
