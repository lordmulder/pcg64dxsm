# [Prerequisites]
# Please see: https://github.com/lordmulder/rust-xbuild/blob/master/Dockerfile

SHELL = /bin/bash
.SHELLFLAGS = -eo pipefail -c

ifneq (Linux,$(shell uname -s))
$(error Error: This script is supposed to run on a Linux system!)
endif

ifneq (x86_64,$(shell uname -m))
$(error Error: This script is supposed to run on the 'x86_64' architecture!)
endif

ifneq (,$(shell git status --porcelain))
$(error Git: Uncommitted changes detected. Cowardly refusing to create an empty archive!)
endif

unexport RUSTFLAGS
unexport RUSTC_BOOTSTRAP

.ONESHELL:
.PHONY: all build wbuild xbuild doc dist pkg clean

all: clean pkg

build:
	mkdir -p out/target/release /tmp/rust-build
	export CARGO_TARGET_DIR="$$(mktemp --tmpdir=/tmp/rust-build -d)"
	for t in x86_64 i686 aarch64; do
		RUSTFLAGS="-Dwarnings -Clinker=$$t-linux-gnu-gcc -Ctarget-feature=+crt-static -Copt-level=3 -Cdebuginfo=none -Ccodegen-units=1 -Cpanic=abort -Clink-arg=-s -Clink-arg=-Ofast" \
		TARGET_CC=/usr/local/musl/$$t/bin/musl-gcc \
		cargo build --release --target $$t-unknown-linux-musl --verbose
		[ "$$t" = "i686" ] && suffix=i686-sse2 || suffix=$$t
		install -v --mode 555 -s --strip-program=$$t-linux-gnu-strip $${CARGO_TARGET_DIR}/$$t-unknown-linux-musl/release/pcg64dxsm out/target/release/pcg64dxsm-$$suffix
		rm -rf $${CARGO_TARGET_DIR}
	done

wbuild:
	mkdir -p out/target/release /tmp/rust-build
	export CARGO_TARGET_DIR="$$(mktemp --tmpdir=/tmp/rust-build -d)"
	RUSTFLAGS="-Dwarnings -Clinker=x86_64-linux-gnu-gcc -Ctarget-feature=+crt-static -Copt-level=3 -Cdebuginfo=none -Ccodegen-units=1 -Cpanic=abort -Clink-arg=-s -Clink-arg=-Ofast -Ctarget-cpu=x86-64-v3" \
	TARGET_CC=/usr/local/musl/x86_64/bin/musl-gcc \
	cargo build --release --target x86_64-unknown-linux-musl --verbose
	install -v --mode 555 -s --strip-program=x86_64-linux-gnu-strip $${CARGO_TARGET_DIR}/x86_64-unknown-linux-musl/release/pcg64dxsm out/target/release/pcg64dxsm-x86_64-v3
	rm -rf $${CARGO_TARGET_DIR}

xbuild:
	mkdir -p out/target/release /tmp/rust-build
	export CARGO_TARGET_DIR="$$(mktemp --tmpdir=/tmp/rust-build -d)"
	for p in i586:i686 riscv64gc:riscv64 powerpc64le:powerpc64le; do
		IFS=":" read -r -a q <<< "$$p"
		RUSTFLAGS="-Dwarnings -Clinker=$${q[1]}-linux-gnu-gcc -Ctarget-feature=+crt-static -Copt-level=3 -Cdebuginfo=none -Ccodegen-units=1 -Cpanic=abort -Clink-arg=-s -Clink-arg=-Ofast" \
		cargo build --release --target $${q[0]}-unknown-linux-musl --verbose
		install -v --mode 555 -s --strip-program=$${q[1]}-linux-gnu-strip $${CARGO_TARGET_DIR}/$${q[0]}-unknown-linux-musl/release/pcg64dxsm out/target/release/pcg64dxsm-$${q[0]}
		rm -rf $${CARGO_TARGET_DIR}
	done

doc:
	mkdir -p out/target/release /tmp/rust-build
	export CARGO_TARGET_DIR="$$(mktemp --tmpdir=/tmp/rust-build -d)"
	RUSTFLAGS=-Dwarnings cargo pkgid | grep -Eo '[^#@]+$$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$$//' > out/target/.PKG_VERSION
	printf '%s\n\n' "$$(RUSTFLAGS=-Dwarnings cargo --version --verbose)" > out/target/.RUSTC_VERSION
	printf '%s\n' "$$(RUSTFLAGS=-Dwarnings cargo rustc --manifest-path ../.auxiliary-files/blank-project/Cargo.toml -- --version --verbose)" >> out/target/.RUSTC_VERSION
	rm -rf $${CARGO_TARGET_DIR}

dist: build wbuild xbuild doc
	cp -f ../../LICENSE ../../README.md out/target/release
	printf 'Revision: %s\n' "$$(git describe --long --tags --always --dirty)" > out/target/release/BUILD_INFO
	printf 'Built: %s\n\n' "$$(date +'%Y-%m-%d %H:%M:%S')" >> out/target/release/BUILD_INFO
	cat out/target/.RUSTC_VERSION >> out/target/release/BUILD_INFO
	find out/target/release -type f -not -name 'pcg64dxsm-*' -exec chmod 444 {} \;

pkg: dist
	IFS= read -r PKG_VERSION < out/target/.PKG_VERSION
	( cd out/target/release && XZ_OPT=-9e tar --owner=0 --group=0 -cJvf ../pcg64dxsm-$${PKG_VERSION}-linux.tar.xz * )
	chmod 444 out/target/pcg64dxsm-$${PKG_VERSION}-linux.*

clean:
	rm -rf out/target
