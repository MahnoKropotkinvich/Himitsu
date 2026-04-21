//! Build script for cifer-sys: compiles the CiFEr C library and
//! generates Rust FFI bindings via bindgen.
//!
//! NOTE: CiFEr requires GMP and libsodium to be installed on the system.
//!   macOS:  brew install gmp libsodium
//!   Ubuntu: apt install libgmp-dev libsodium-dev

use std::env;
use std::path::PathBuf;

fn main() {
    let cifer_root = PathBuf::from("../vendor/CiFEr");

    if !cifer_root.join("include").exists() {
        println!("cargo:warning=CiFEr source not found at {:?}. Skipping C compilation.", cifer_root);
        println!("cargo:warning=Run: git submodule update --init --recursive");
        return;
    }

    // Collect CiFEr C source files
    let src_dir = cifer_root.join("src");
    let mut c_files: Vec<PathBuf> = Vec::new();
    collect_c_files(&src_dir, &mut c_files);

    if c_files.is_empty() {
        println!("cargo:warning=No .c files found in CiFEr source tree.");
        return;
    }

    // Compile CiFEr
    let mut build = cc::Build::new();
    build
        .include(cifer_root.join("include"))
        .include(cifer_root.join("external"))
        .warnings(false)
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare");

    for f in &c_files {
        build.file(f);
    }

    build.compile("cifer");

    // Link system dependencies
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=sodium");

    // Generate bindings with bindgen
    let bindings = bindgen::Builder::default()
        .header(cifer_root.join("include/cifer/innerprod/fullysec/damgard.h").to_str().unwrap())
        .header(cifer_root.join("include/cifer/innerprod/simple/ddh.h").to_str().unwrap())
        .clang_arg(format!("-I{}", cifer_root.join("include").display()))
        .clang_arg(format!("-I{}", cifer_root.join("external").display()))
        .allowlist_function("cfe_.*")
        .allowlist_type("cfe_.*")
        .generate()
        .expect("Unable to generate CiFEr bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("cifer_bindings.rs"))
        .expect("Couldn't write bindings");
}

fn collect_c_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_c_files(&path, out);
            } else if path.extension().map_or(false, |e| e == "c") {
                out.push(path);
            }
        }
    }
}
