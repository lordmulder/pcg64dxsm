// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use blake2::{Blake2b256, Digest};
use hex::{FromHexError, decode_to_slice};
use hex_literal::hex;
use std::{
    ffi::OsStr,
    fmt::UpperHex,
    io::Read,
    mem::MaybeUninit,
    process::{Command, Stdio},
};

const BUFFER_SIZE: usize = 64usize * 1024usize; // 64 KB
const OUTPUT_SIZE: u64 = 16u64 * 1024u64 * 1024u64 * 1024u64; // 16 GB

const ENTROPY_SIZE: u64 = 16u64 * 1024u64 * 1024u64; // 16 MB
const ENTROPY_ITER: usize = 1024usize;

// ===========================================================================
// Types
// ===========================================================================

/// The aligned byte buffer (64 bytes)
#[repr(align(32))]
struct AlignedBuffer<const CAPACITY: usize>(pub [u8; CAPACITY]);

impl<const CAPACITY: usize> AlignedBuffer<CAPACITY> {
    fn uninit() -> Self {
        let array: MaybeUninit<[u8; CAPACITY]> = MaybeUninit::uninit();
        Self(unsafe { array.assume_init() })
    }
}

// ===========================================================================
// Hex Support
// ===========================================================================

struct Hex<'a>(&'a [u8]);

impl UpperHex for Hex<'_> {
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
    buffer: AlignedBuffer<N>,
    offset: usize,
}

impl<const N: usize> HexDecoder<N> {
    pub fn new() -> Self {
        const {
            assert!((N > 0usize) && (N & 1usize == 0usize));
        }
        Self { buffer: AlignedBuffer::uninit(), offset: 0usize }
    }

    pub fn decode_inplace<'a>(&mut self, input: &'a mut [u8]) -> Result<&'a [u8], FromHexError> {
        let mut pos_get = 0usize;
        let mut pos_put = 0usize;

        while pos_get < input.len() {
            let copy_len = input.len().saturating_sub(pos_get).min(N.saturating_sub(self.offset));
            if copy_len > 0usize {
                self.buffer.0[self.offset..(self.offset + copy_len)].copy_from_slice(&input[pos_get..(pos_get + copy_len)]);
                pos_get = pos_get.checked_add(copy_len).unwrap();
                self.offset = self.offset.checked_add(copy_len).unwrap();
            }

            let decode_len = self.offset & (!1usize);
            if decode_len > 0usize {
                let output_len = decode_len / 2usize;
                decode_to_slice(&self.buffer.0[..decode_len], &mut input[pos_put..(pos_put + output_len)])?;
                if decode_len != self.offset {
                    assert_eq!(self.offset - decode_len, 1usize);
                    self.buffer.0[0usize] = self.buffer.0[self.offset - 1usize];
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

fn run_process<const N: usize>(output_size: Option<u64>, hex_decode: bool, args: [&OsStr; N]) -> [u8; 32usize] {
    let mut child_process = Command::new(env!("CARGO_BIN_EXE_pcg64dxsm"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn the child process!");

    let mut stdout = child_process.stdout.take().expect("No stdout stream!");
    let mut buffer: AlignedBuffer<BUFFER_SIZE> = AlignedBuffer::uninit();
    let mut hex_decoder = if hex_decode { Some(HexDecoder::<8192usize>::new()) } else { None };
    let mut length = 0u64;
    let mut hasher = Blake2b256::default();

    while output_size.is_none_or(|target_size| length < target_size) {
        let read_len = stdout.read(&mut buffer.0).expect("Failed to read data from child process!");
        if read_len == 0usize {
            break;
        }
        if let Some(decoder) = hex_decoder.as_mut() {
            let decoded = decoder.decode_inplace(&mut buffer.0[..read_len]).expect("Failed to decode hex-encoded input!");
            if !decoded.is_empty() {
                let chunk_size = output_size.map(|target_size| target_size.saturating_sub(length).min(decoded.len() as u64) as usize).unwrap_or(decoded.len());
                hasher.update(&decoded[..chunk_size]);
                length = length.checked_add(chunk_size as u64).unwrap();
            }
        } else {
            let chunk_size = output_size.map(|target_size| target_size.saturating_sub(length).min(read_len as u64) as usize).unwrap_or(read_len);
            hasher.update(&buffer.0[..chunk_size]);
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
const PCG64DXSM_0: [u8; 32usize] = hex!("8C8C2C59C1B5726D4B1EFB5DF4F4C3EC92C3A0C49B57D54E67D859D015837B1E");
const PCG64DXSM_1: [u8; 32usize] = hex!("A3CFB4A9425BF51810026B2040A1210C654A43A29E1B81A2330F6FFA2A9C1BA8");
const PCG64DXSM_2: [u8; 32usize] = hex!("7D27FFDEDC2828C34E07B930431382A563AA5C921F95B91C851EC7846DC1D0A5");
const PCG64DXSM_3: [u8; 32usize] = hex!("863CBD556E03EB2566A09B6C426AFCA6B73ECA6EA9B3D8D3AE6E40BC370F1C65");
const PCG64FAST_0: [u8; 32usize] = hex!("530DB3020B62F70DE571A73590AD7DA4CF890BE3FF87045AA3D6A6C2EB88574C");
const PCG64FAST_1: [u8; 32usize] = hex!("8C216782F5B5F391C3B9BF7B8B892E0617944C928FF45C38DAC0E48BE71E3E4D");
const PCG64FAST_2: [u8; 32usize] = hex!("5DA2BCF0ABAEB18D8349CDBC035DCD580E1F14FC874F3D7442E0E94D467D55FD");
const PCG64FAST_3: [u8; 32usize] = hex!("4DFD11A735898B08876150056574E3FC2FDEBE0A8862E0787EC31293E8518EF9");

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
    let mut digest_all: Vec<[u8; 32usize]> = Vec::with_capacity(ENTROPY_ITER);
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
    let mut digest_all: Vec<[u8; 32usize]> = Vec::with_capacity(ENTROPY_ITER);
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
