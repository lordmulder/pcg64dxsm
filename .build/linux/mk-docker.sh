#!/bin/bash
set -eo pipefail
cd -- "$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")")"

unset RUSTC_BOOTSTRAP
readonly IMAGE_SPEC=lordmulder/rust-xbuild:1.94-trixie-r4

set -x
exec docker run --rm -v "${PWD}/../..":/workspace:ro -v "${PWD}/out":/workspace/.build/linux/out --tmpfs /tmp/rust-build:rw,exec -w /workspace "${IMAGE_SPEC}" make -C .build/linux
