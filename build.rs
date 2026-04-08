// SPDX-License-Identifier: Unlicense
// pcg64dxsm application
// Copyright (C) 2026 by LoRd_MuldeR <mulder2@gmx.de>

use chrono::{SecondsFormat, Utc};

#[cfg(windows)]
fn build_windows_resources() {
    let mut winres = winres::WindowsResource::new();
    winres.set_icon(r"resources\app.ico");
    winres.set_manifest_file(&format!(r"resources\app-{}.manifest", std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()));
    winres.compile().expect("Windows resource compiler has failed!");
}

fn main() {
    println!("cargo:rustc-env=BUILD_DATE={}", Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    #[cfg(windows)]
    build_windows_resources();
}
