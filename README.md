# Lcg128CmDxsm64

Blazing fast random number generator based on Lcg128CmDxsm64 (CM DXSM 128/64 LCG).

Permuted Congruential Generator (PCG) with 128-bit state, internal Linear Congruential Generator (LCG), and 64-bit output via “double xorshift multiply” (DXSM) output function; also known as `PCG64DXSM`. Despite the name, this implementation uses 32 bytes (256 bit) space comprising 128 bits of state and 128 bits stream selector. It can be seeded from the OS' entropy source or with a user-defined seed value for reproducible output.

This application is built upon the [`rand_pcg`](https://crates.io/crates/rand_pcg) crate, by Jeb Brooks. Please see [**`Lcg128CmDxsm64`**](https://docs.rs/rand_pcg/latest/rand_pcg/struct.Lcg128CmDxsm64.html) for details! &#128161;

## Manual

```
Usage: pcg64dxsm [OPTIONS] [SEED]

Arguments:
  [SEED]  User-defined seed value; if not specified, seed from OS entropy source

Options:
  -t, --thread   Enable multi-threading
  -h, --help     Print help
  -V, --version  Print version
```

## License

This software is released under the BSD Zero Clause (“0BSD”) License.

Copyright (C) 2026 by LoRd_MuldeR &lt;mulder2@gmx.de&gt;.
