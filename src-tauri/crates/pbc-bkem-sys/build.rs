use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bkem_dir = manifest_dir.join("../../vendor/PBC_BKEM");

    let bkem_c = bkem_dir.join("bkem.c");
    if !bkem_c.exists() {
        println!("cargo:warning=PBC_BKEM source not found. Run: git submodule update --init --recursive");
        return;
    }

    let dep_paths = DepPaths::detect();

    // --- GMP: always require system library ---
    println!("cargo:rustc-link-lib=gmp");
    for p in &dep_paths.lib_search {
        println!("cargo:rustc-link-search={}", p.display());
    }

    // --- PBC: prefer system library, fall back to vendored source ---
    let use_system_pbc = try_system_pbc(&dep_paths);

    if !use_system_pbc {
        println!("cargo:warning=System libpbc not found, building from vendored source");
        build_vendored_pbc(&dep_paths);
    }

    // --- Build bkem.c (from submodule) + bkem_helpers.c (local to this crate) ---
    let is_msvc = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc";
    let mut bkem_build = cc::Build::new();
    bkem_build
        .file(&bkem_c)
        .file(manifest_dir.join("bkem_helpers.c"))
        .include(&bkem_dir)
        .warnings(false);

    for p in &dep_paths.include {
        bkem_build.include(p);
    }

    if is_msvc {
        // PBC headers use GCC __attribute__ which MSVC doesn't understand.
        // PBC ships pbc_vc_compat.win32.h but it redefines snprintf which
        // conflicts with VS2015+ CRT.  Define only what we actually need.
        msvc_pbc_compat(&mut bkem_build);
    }

    if use_system_pbc {
        // System PBC headers already covered by dep_paths.include
    } else {
        // Vendored PBC: create shim so `#include <pbc/pbc.h>` resolves
        let pbc_dir = bkem_dir.join("../pbc");
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let shim_dir = out_dir.join("pbc_include/pbc");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let pbc_include = pbc_dir.join("include");
        if let Ok(entries) = std::fs::read_dir(&pbc_include) {
            for entry in entries.flatten() {
                let dest = shim_dir.join(entry.file_name());
                let _ = std::fs::remove_file(&dest);
                #[cfg(unix)]
                std::os::unix::fs::symlink(entry.path(), &dest).ok();
                #[cfg(windows)]
                std::fs::copy(entry.path(), &dest).ok();
            }
        }
        bkem_build.include(out_dir.join("pbc_include"));
        bkem_build.include(pbc_dir.join("include"));
        bkem_build.include(&pbc_dir);
    }

    bkem_build.compile("bkem");

    // --- Generate Rust bindings ---
    let mut bindgen_builder = bindgen::Builder::default()
        .header(manifest_dir.join("bkem_wrapper.h").to_str().unwrap())
        .clang_arg(format!("-I{}", bkem_dir.display()));

    for p in &dep_paths.include {
        bindgen_builder = bindgen_builder.clang_arg(format!("-I{}", p.display()));
    }

    // bindgen always uses libclang which understands __attribute__, but when
    // targeting MSVC the default defines may differ; ensure compat just in case.
    if is_msvc {
        bindgen_builder = bindgen_builder
            .clang_arg("-D__attribute__(x)=")
            .clang_arg("-D_CRT_SECURE_NO_WARNINGS");

        // libclang doesn't know MSVC's CRT/SDK include paths by default.
        // Tell it we're targeting MSVC and pass the system include dirs
        // so it can find stdio.h and friends.
        bindgen_builder = bindgen_builder
            .clang_arg("--target=x86_64-pc-windows-msvc");
        for p in msvc_system_include_paths() {
            bindgen_builder = bindgen_builder.clang_arg(format!("-isystem{}", p));
        }
    }

    if !use_system_pbc {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let pbc_dir = bkem_dir.join("../pbc");
        bindgen_builder = bindgen_builder
            .clang_arg(format!("-I{}", out_dir.join("pbc_include").display()))
            .clang_arg(format!("-I{}", pbc_dir.join("include").display()))
            .clang_arg(format!("-I{}", pbc_dir.display()));
    }

    let bindings = bindgen_builder
        .allowlist_function("setup_global_system")
        .allowlist_function("setup")
        .allowlist_function("get_encryption_key")
        .allowlist_function("get_decryption_key")
        .allowlist_function("free_global_params")
        .allowlist_function("free_bkem_system")
        .allowlist_function("free_pubkey")
        .allowlist_function("himitsu_element_to_bytes")
        .allowlist_function("himitsu_element_from_bytes")
        .allowlist_function("himitsu_element_length_in_bytes")
        .allowlist_function("himitsu_element_init_GT")
        .allowlist_function("himitsu_element_init_G1")
        .allowlist_function("himitsu_element_clear")
        .allowlist_function("himitsu_element_cmp")
        .generate()
        .expect("Failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");

    println!("cargo:rerun-if-changed={}", bkem_c.display());
    println!("cargo:rerun-if-changed={}", bkem_dir.join("bkem.h").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("bkem_wrapper.h").display());
    println!("cargo:rerun-if-changed={}", manifest_dir.join("bkem_helpers.c").display());
}

// ---------------------------------------------------------------------------
// Platform-aware dependency paths
// ---------------------------------------------------------------------------

/// Include and library search paths for GMP/PBC, resolved per platform.
struct DepPaths {
    include: Vec<PathBuf>,
    lib_search: Vec<PathBuf>,
}

impl DepPaths {
    fn detect() -> Self {
        let mut include = Vec::new();
        let mut lib_search = Vec::new();

        // 1. Environment overrides (set by CI or user) take priority.
        //    GMP_INCLUDE_DIR / GMP_LIB_DIR — used by vcpkg on Windows.
        if let Ok(dir) = env::var("GMP_INCLUDE_DIR") {
            include.push(PathBuf::from(dir));
        }
        if let Ok(dir) = env::var("GMP_LIB_DIR") {
            lib_search.push(PathBuf::from(dir));
        }
        // Also check the generic C_INCLUDE_PATH / LIBRARY_PATH
        if let Ok(dirs) = env::var("C_INCLUDE_PATH") {
            for d in env::split_paths(&dirs) {
                include.push(d);
            }
        }
        if let Ok(dirs) = env::var("INCLUDE") {
            for d in env::split_paths(&dirs) {
                include.push(d);
            }
        }
        if let Ok(dirs) = env::var("LIBRARY_PATH") {
            for d in env::split_paths(&dirs) {
                lib_search.push(d);
            }
        }

        // 2. Platform-specific well-known paths (Unix only).
        //    On Windows these don't exist and would cause cl.exe to error.
        if !cfg!(target_os = "windows") {
            let unix_include = [
                "/opt/homebrew/include",
                "/usr/local/include",
                "/usr/include",
            ];
            let unix_lib = [
                "/opt/homebrew/lib",
                "/usr/local/lib",
                "/usr/lib",
                "/usr/lib/x86_64-linux-gnu",
            ];
            for p in unix_include {
                let pb = PathBuf::from(p);
                if pb.exists() && !include.contains(&pb) {
                    include.push(pb);
                }
            }
            for p in unix_lib {
                let pb = PathBuf::from(p);
                if pb.exists() && !lib_search.contains(&pb) {
                    lib_search.push(pb);
                }
            }
        }

        DepPaths { include, lib_search }
    }
}

// ---------------------------------------------------------------------------
// System PBC detection
// ---------------------------------------------------------------------------

fn try_system_pbc(dep: &DepPaths) -> bool {
    // pkg-config (Unix)
    if !cfg!(target_os = "windows") {
        if let Ok(status) = std::process::Command::new("pkg-config")
            .args(["--exists", "pbc"])
            .status()
        {
            if status.success() {
                if let Ok(output) = std::process::Command::new("pkg-config")
                    .args(["--libs", "pbc"])
                    .output()
                {
                    let libs = String::from_utf8_lossy(&output.stdout);
                    for token in libs.split_whitespace() {
                        if let Some(lib) = token.strip_prefix("-l") {
                            println!("cargo:rustc-link-lib={lib}");
                        } else if let Some(path) = token.strip_prefix("-L") {
                            println!("cargo:rustc-link-search={path}");
                        }
                    }
                    println!("cargo:warning=Using system libpbc (via pkg-config)");
                    return true;
                }
            }
        }
    }

    // Search well-known lib paths (already platform-filtered in DepPaths)
    for path in &dep.lib_search {
        let found = path.join("libpbc.dylib").exists()
            || path.join("libpbc.so").exists()
            || path.join("libpbc.a").exists()
            || path.join("pbc.lib").exists();
        if found {
            println!("cargo:rustc-link-search={}", path.display());
            println!("cargo:rustc-link-lib=pbc");
            println!("cargo:warning=Using system libpbc (found in {})", path.display());
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Vendored PBC build
// ---------------------------------------------------------------------------

fn build_vendored_pbc(dep: &DepPaths) {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let pbc_dir = manifest_dir.join("../../vendor/pbc");

    if !pbc_dir.join("include/pbc.h").exists() {
        println!("cargo:warning=PBC source not found at {:?}. Run: git submodule update --init --recursive", pbc_dir);
        panic!("PBC source required but not found");
    }

    let is_msvc = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc";

    let pbc_srcs = [
        // arith
        "arith/field.c",
        "arith/fp.c",
        "arith/montfp.c",
        "arith/naivefp.c",
        "arith/fastfp.c",
        "arith/fasterfp.c",
        "arith/multiz.c",
        "arith/z.c",
        "arith/fieldquadratic.c",
        "arith/poly.c",
        "arith/ternary_extension_field.c",
        "arith/random.c",
        "arith/dlog.c",
        "arith/init_random.c",
        // ecc
        "ecc/curve.c",
        "ecc/singular.c",
        "ecc/pairing.c",
        "ecc/param.c",
        "ecc/a_param.c",
        "ecc/d_param.c",
        "ecc/e_param.c",
        "ecc/f_param.c",
        "ecc/g_param.c",
        "ecc/eta_T_3.c",
        "ecc/hilbert.c",
        "ecc/mnt.c",
        "ecc/mpc.c",
        // misc
        "misc/utils.c",
        "misc/darray.c",
        "misc/symtab.c",
        "misc/extend_printf.c",
        "misc/memory.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(pbc_dir.join("include"))
        .include(&pbc_dir)
        .warnings(false)
        .opt_level(3)
        .flag_if_supported("-ffast-math")
        .flag_if_supported("-fomit-frame-pointer");

    for p in &dep.include {
        build.include(p);
    }

    if is_msvc {
        // Same MSVC compat as bkem_build above.
        msvc_pbc_compat(&mut build);
    }

    for src in &pbc_srcs {
        let path = pbc_dir.join(src);
        if path.exists() {
            build.file(&path);
        } else {
            println!("cargo:warning=PBC source file not found: {}", path.display());
        }
    }

    // get_time.c uses sys/time.h + gettimeofday (POSIX only).
    // On Windows we compile a Win32 replacement instead.
    if is_msvc {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let stub = out_dir.join("pbc_get_time_win32.c");
        std::fs::write(&stub, PBC_GET_TIME_WIN32).unwrap();
        build.file(&stub);
    } else {
        let gt = pbc_dir.join("misc/get_time.c");
        if gt.exists() {
            build.file(&gt);
        }
    }

    build.compile("pbc_vendored");
    println!("cargo:warning=Built PBC from vendored source");
}

/// Win32 replacement for PBC's misc/get_time.c (which requires POSIX sys/time.h).
const PBC_GET_TIME_WIN32: &str = r#"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

double pbc_get_time(void) {
    static LARGE_INTEGER freq;
    static LARGE_INTEGER last;
    static int first = 1;
    static double res = 0.0;
    LARGE_INTEGER now;

    if (first) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&last);
        first = 0;
        return 0.0;
    }
    QueryPerformanceCounter(&now);
    res += (double)(now.QuadPart - last.QuadPart) / (double)freq.QuadPart;
    last = now;
    return res;
}
"#;

/// Apply MSVC compatibility for compiling PBC C sources.
///
/// PBC headers use GCC extensions (`__attribute__`, `__func__`) that MSVC
/// doesn't understand. PBC ships `pbc_vc_compat.win32.h` but it redefines
/// `snprintf` to `_snprintf`, which conflicts with VS2015+ CRT.
///
/// MSVC's `/D` flag cannot define function-like macros (`__attribute__(x)`),
/// so we generate a minimal compat header into OUT_DIR and force-include it.
fn msvc_pbc_compat(build: &mut cc::Build) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let compat_h = out_dir.join("himitsu_pbc_compat.h");
    std::fs::write(&compat_h, MSVC_PBC_COMPAT_H).unwrap();

    build.define("_CRT_SECURE_NO_WARNINGS", None);
    build.flag("/FI");
    build.flag(compat_h.to_str().unwrap());
}

/// Minimal MSVC compatibility header for PBC.
/// Replaces pbc_vc_compat.win32.h without the snprintf conflict.
const MSVC_PBC_COMPAT_H: &str = r#"
#pragma once

/* Define away GCC __attribute__ — used for format, noreturn, unused */
#define __attribute__(x)

/* PBC uses bare `inline` (C99 inline semantics) which does not emit an
   external definition in MSVC's C mode. Removing the keyword forces the
   compiler to emit a regular (externally visible) function body. */
#define inline

/* __func__ is a GCC/C99 built-in; MSVC provides __FUNCTION__ */
#ifndef __func__
#define __func__ __FUNCTION__
#endif
"#;

/// Detect MSVC system include paths (UCRT + MSVC CRT) for libclang.
///
/// libclang does not automatically discover MSVC headers the way cl.exe does.
/// We probe the `cc` crate's tool detection to find where cl.exe lives,
/// then derive the MSVC and Windows SDK include directories.
fn msvc_system_include_paths() -> Vec<String> {
    let mut paths = Vec::new();

    // The cc crate's Build::get_compiler() runs vcvars detection internally.
    // We can use its include paths by inspecting the INCLUDE env var that
    // the CI or vcvars sets, or by probing vswhere.
    //
    // Strategy: use the INCLUDE environment variable which `cc` and MSVC
    // build tools typically populate. If the CI sets it partially (only
    // vcpkg), we augment with vswhere-discovered paths.

    // First, try the full MSVC INCLUDE env var (set by vcvarsall.bat or CI)
    if let Ok(include_env) = env::var("INCLUDE") {
        for p in include_env.split(';') {
            let p = p.trim();
            if !p.is_empty() {
                paths.push(p.to_string());
            }
        }
    }

    // Try to find MSVC and UCRT paths via vswhere + known layout
    if let Some(vs_path) = find_vs_install_path() {
        // Find the MSVC tools version
        let tools_dir = vs_path.join("VC/Tools/MSVC");
        if let Ok(entries) = std::fs::read_dir(&tools_dir) {
            if let Some(latest) = entries
                .flatten()
                .filter(|e| e.path().is_dir())
                .max_by_key(|e| e.file_name())
            {
                let msvc_include = latest.path().join("include");
                if msvc_include.exists() {
                    let s = msvc_include.to_string_lossy().to_string();
                    if !paths.contains(&s) {
                        paths.push(s);
                    }
                }
            }
        }
    }

    // Windows SDK (UCRT) — usually under C:\Program Files (x86)\Windows Kits\10
    let sdk_root = PathBuf::from(
        env::var("WindowsSdkDir")
            .unwrap_or_else(|_| r"C:\Program Files (x86)\Windows Kits\10".to_string()),
    );
    let ucrt_base = sdk_root.join("Include");
    if let Ok(entries) = std::fs::read_dir(&ucrt_base) {
        if let Some(latest) = entries
            .flatten()
            .filter(|e| e.path().is_dir() && e.file_name().to_string_lossy().starts_with("10."))
            .max_by_key(|e| e.file_name())
        {
            let ver_dir = latest.path();
            for sub in &["ucrt", "shared", "um"] {
                let p = ver_dir.join(sub);
                if p.exists() {
                    let s = p.to_string_lossy().to_string();
                    if !paths.contains(&s) {
                        paths.push(s);
                    }
                }
            }
        }
    }

    paths
}

/// Find Visual Studio installation path using vswhere.
fn find_vs_install_path() -> Option<PathBuf> {
    let vswhere = PathBuf::from(
        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
    );
    if !vswhere.exists() {
        return None;
    }
    let output = std::process::Command::new(&vswhere)
        .args(["-latest", "-property", "installationPath", "-nologo"])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}
