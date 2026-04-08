#!/bin/bash
set -e
exec > >(tee results_mt.txt)

cargo clean
cargo bench --no-run

for k in 4 8 16 32 64; do
    for i in 16384 32768 65536 131072; do
        PCG64DXSM_MT_BUFFER_SIZE=${i} PCG64DXSM_MT_NUM_BUFFERS=${k} cargo bench --bench rng_bench -- --mt
        printf '\n'
    done
done
