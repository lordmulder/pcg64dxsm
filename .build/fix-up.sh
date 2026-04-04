#!/bin/bash
set -e
cd -- "$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/..")"

cargo clean
cargo upgrade --recursive --incompatible
cargo update
cargo fmt --all
cargo clippy --all-targets --all-features
cargo build --release

echo "Completed successfully."
