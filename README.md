# Lcg128CmDxsm64

Blazing fast random number generator based on **Lcg128CmDxsm64** (CM DXSM 128/64 LCG).

Permuted Congruential Generator (PCG) with 128-bit state, internal Linear Congruential Generator (LCG), and 64-bit output via “double xorshift multiply” (DXSM) output function; also known as **`pcg64_dxsm`**. Despite the name, this implementation uses 32 bytes (256 bit) space comprising 128 bits of state and 128 bits stream selector. It can be seeded from the OS' entropy source or with a user-defined seed value for reproducible output.

Optionally, `--fast` mode uses the **Mcg128Xsl64** (XSL 128/64 MCG) random number generator; also known as **`pcg64_fast`**. It runs even faster, but may provide slightly worse (but still good) statistical properties.

## Manual

```
Usage: pcg64dxsm [OPTIONS] [SEED]

Arguments:
  [SEED]  User-defined seed value; if not specified, seed from OS entropy source

Options:
  -t, --thread   Enable multi-threaded random number generation
  -f, --fast     Use faster algorithm, with slightly worse statistical properties
  -h, --help     Print help
  -V, --version  Print version
```

## Acknowledgement

### PCG random number generators

This application is built upon the [**`rand_pcg`**](https://crates.io/crates/rand_pcg) create, created by the Rand project contributors.

Please see [`Lcg128CmDxsm64`](https://docs.rs/rand_pcg/latest/rand_pcg/struct.Lcg128CmDxsm64.html) and [`Mcg128Xsl64`](https://docs.rs/rand_pcg/latest/rand_pcg/struct.Mcg128Xsl64.html) for details! 

`rand_pcg` is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

### Dice icon

This application uses the [Dice icon](https://www.flaticon.com/free-icons/dice) created by Prosymbols Premium.

Provided under the Flaticon License. Free for personal and commercial purpose with attribution.

## License

This is free and unencumbered software released into the public domain.

Created by LoRd_MuldeR &lt;mulder2@gmx.de&gt;.
