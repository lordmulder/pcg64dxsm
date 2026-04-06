#!/bin/bash
set -eo pipefail
cd -- "$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")")"

unset RUSTC_BOOTSTRAP

readonly IMAGE_SPEC="$(cat ../../.github/workflows/ci.yml | grep -PA4 '^\s*build-linux:' | grep -Pom1 'lordmulder/rust-xbuild:[^\s:]+')"
if [ -z "${IMAGE_SPEC}" ]; then
	echo "Error: Failed to determine Docker image version!"
	exit 1
fi

set -x
exec docker run --rm -v "${PWD}/../..":/workspace:ro -v "${PWD}/out":/workspace/.build/linux/out --tmpfs /tmp/rust-build:rw,exec -w /workspace "${IMAGE_SPEC}" make -C .build/linux
