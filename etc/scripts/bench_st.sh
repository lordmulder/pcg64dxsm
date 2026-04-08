#!/bin/bash
set -e
exec > >(tee results_st.txt)

cargo clean
cargo bench --no-run

for i in 8192 16384 32768 65536 131072; do
    PCG64DXSM_ST_BUFFER_SIZE=${i} cargo bench --bench rng_bench -- --st
    printf '\n'
done
