MY_ARCH = x86_64
MY_OS = unix
MY_OUTFILENAME = $(MY_OS)
MY_VENDOR = unknown

.PHONY: all build doc dist pkg clean

all: clean pkg

build:
	set -e; \
	mkdir -p out/target/release; \
	export CARGO_TARGET_DIR="`mktemp -d`"; \
	for t in $(MY_ARCH); do \
		cargo build --release --target "$$t-$(MY_VENDOR)-$(MY_OS)" --verbose; \
		cp -f $${CARGO_TARGET_DIR}/$$t-$(MY_VENDOR)-$(MY_OS)/release/pcg64dxsm out/target/release/pcg64dxsm-$$t; \
		chmod 555 out/target/release/pcg64dxsm-$$t; \
		rm -rf $${CARGO_TARGET_DIR}; \
	done

doc:
	set -e; \
	mkdir -p out/target/release; \
	export CARGO_TARGET_DIR="`mktemp -d`"; \
	RUSTFLAGS=-Dwarnings cargo pkgid | sed 's/^.*#//;s/^[[:space:]]*//;s/[[:space:]]*$$//' > out/target/.PKG_VERSION; \
	printf '%s\n\n' "`RUSTFLAGS=-Dwarnings cargo --version --verbose`" > out/target/.RUSTC_VERSION; \
	printf '%s\n' "`RUSTFLAGS=-Dwarnings cargo rustc --manifest-path ../.auxiliary-files/blank-project/Cargo.toml -- --version --verbose`" >> out/target/.RUSTC_VERSION; \
	rm -rf $${CARGO_TARGET_DIR}

dist: build doc
	set -e; \
	cp -f ../../LICENSE ../../README.md out/target/release/; \
	printf 'Revision: %s\n' "`git describe --long --tags --always --dirty`" > out/target/release/BUILD_INFO; \
	printf 'Built: %s\n\n' "`date +'%Y-%m-%d %H:%M:%S'`" >> out/target/release/BUILD_INFO; \
	cat out/target/.RUSTC_VERSION >> out/target/release/BUILD_INFO; \
	find out/target/release -type f ! -name 'pcg64dxsm-*' -exec chmod 444 {} \;; \
	find out/target/release -type d -exec chmod 755 {} \;

pkg: dist
	set -e; \
	IFS= read -r PKG_VERSION < out/target/.PKG_VERSION; \
	( cd out/target/release && tar -cf ../pcg64dxsm-$${PKG_VERSION}-$(MY_OUTFILENAME).tar * ); \
	xz -9 out/target/pcg64dxsm-$${PKG_VERSION}-$(MY_OUTFILENAME).tar; \
	chmod 444 out/target/*.tar.xz

clean:
	rm -rf out/target
