#!/bin/sh
set -e

# [Prerequisites]
# - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.92.0
# - rustup target add x86_64-apple-darwin

if [ "$(uname -s)" != "Darwin" ]; then
    echo "Error: This script is supposed to run on a Darwin (macOS) system!"
    exit 1
fi

if [ "$(uname -m)" != "arm64" ]; then
    echo "Error: This script is supposed to run on the 'amd64' architecture!"
    exit 1
fi

unset RUSTC_BOOTSTRAP

RUSTFLAGS="-Dwarnings -Ctarget-feature=+crt-static -Copt-level=3 -Cdebuginfo=none -Ccodegen-units=1 -Cpanic=abort" \
make MY_VENDOR=apple MY_OS=darwin MY_OUTFILENAME=macos MY_ARCH="aarch64 x86_64"

IFS= read -r PKG_VERSION < out/target/.PKG_VERSION
hdiutil create -ov -volname "pcg64dxsm ${PKG_VERSION}" -fs HFS+ -srcfolder out/target/release out/target/pcg64dxsm-${PKG_VERSION}-macos.dmg
hdiutil convert -format UDZO -imagekey zlib-level=9 -o out/target/pcg64dxsm-${PKG_VERSION}-macos_compressed.dmg out/target/pcg64dxsm-${PKG_VERSION}-macos.dmg
mv -vf out/target/pcg64dxsm-${PKG_VERSION}-macos_compressed.dmg out/target/pcg64dxsm-${PKG_VERSION}-macos.dmg
chmod 444 out/target/pcg64dxsm-${PKG_VERSION}-macos.dmg
