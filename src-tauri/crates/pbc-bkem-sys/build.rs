use std::env;
use std::path::PathBuf;

fn main() {
    let bkem_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../..")
        .join("vendor/PBC_BKEM");

    let bkem_c = bkem_dir.join("bkem.c");
    if !bkem_c.exists() {
        println!("cargo:warning=PBC_BKEM source not found. Run: git submodule update --init --recursive");
        return;
    }

    // --- GMP: always require system library ---
    println!("cargo:rustc-link-lib=gmp");

    // --- PBC: prefer system library, fall back to vendored source ---
    let use_system_pbc = try_system_pbc();

    if !use_system_pbc {
        println!("cargo:warning=System libpbc not found, building from vendored source");
        build_vendored_pbc();
    }

    // --- Build bkem.c + bkem_helpers.c ---
    let mut bkem_build = cc::Build::new();
    bkem_build
        .file(&bkem_c)
        .file(bkem_dir.join("bkem_helpers.c"))
        .include(&bkem_dir)
        // Always include GMP system paths (GMP is a hard system dependency)
        .include("/opt/homebrew/include")
        .include("/usr/local/include")
        .include("/usr/include")
        .warnings(false);

    if use_system_pbc {
        // System PBC headers
        bkem_build.include("/opt/homebrew/include");
        bkem_build.include("/usr/local/include");
        bkem_build.include("/usr/include");
    } else {
        // Vendored PBC: include parent of `include/` so `#include <pbc/pbc.h>` resolves
        // PBC header is at vendor/pbc/include/pbc.h, and bkem wants <pbc/pbc.h>
        // So we need a directory where pbc/ subdirectory contains pbc.h
        // Solution: create a symlink or pass the right include path
        let pbc_dir = bkem_dir.join("../pbc");
        // PBC's include dir has pbc.h directly. We need <pbc/pbc.h> to resolve.
        // The parent of the include dir works if include/ were named pbc/.
        // Workaround: pass include's parent and also include itself as "pbc" alias.
        // Actually simplest: the pbc repo has include/pbc.h and include/pbc_*.h
        // We need #include <pbc/pbc.h> → so pass the directory ABOVE include/
        // But that won't work because the file is include/pbc.h not include/pbc/pbc.h
        //
        // Real fix: create a shim directory structure in OUT_DIR
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let shim_dir = out_dir.join("pbc_include/pbc");
        std::fs::create_dir_all(&shim_dir).unwrap();
        // Symlink all PBC headers into the shim pbc/ directory
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
        .header(bkem_dir.join("bkem_wrapper.h").to_str().unwrap())
        .clang_arg(format!("-I{}", bkem_dir.display()))
        // GMP system headers (always needed)
        .clang_arg("-I/opt/homebrew/include")
        .clang_arg("-I/usr/local/include");

    if use_system_pbc {
        bindgen_builder = bindgen_builder
            .clang_arg("-I/opt/homebrew/include")
            .clang_arg("-I/usr/local/include");
    } else {
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
    println!("cargo:rerun-if-changed={}", bkem_dir.join("bkem_wrapper.h").display());
    println!("cargo:rerun-if-changed={}", bkem_dir.join("bkem_helpers.c").display());
}

/// Try to find system-installed libpbc via pkg-config or common paths.
fn try_system_pbc() -> bool {
    // Try pkg-config first
    if let Ok(status) = std::process::Command::new("pkg-config")
        .args(["--exists", "pbc"])
        .status()
    {
        if status.success() {
            // Use pkg-config to get the right flags
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

    // Try common library paths directly
    let search_paths = [
        "/opt/homebrew/lib",
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
    ];

    for path in &search_paths {
        let lib_path = PathBuf::from(path);
        let dylib = lib_path.join("libpbc.dylib");
        let so = lib_path.join("libpbc.so");
        let a = lib_path.join("libpbc.a");
        if dylib.exists() || so.exists() || a.exists() {
            println!("cargo:rustc-link-search={path}");
            println!("cargo:rustc-link-lib=pbc");
            println!("cargo:warning=Using system libpbc (found in {path})");
            return true;
        }
    }

    false
}

/// Build PBC from vendored source (vendor/pbc/).
fn build_vendored_pbc() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let pbc_dir = manifest_dir.join("../../vendor/pbc");

    if !pbc_dir.join("include/pbc.h").exists() {
        println!("cargo:warning=PBC source not found at {:?}. Run: git submodule update --init --recursive", pbc_dir);
        panic!("PBC source required but not found");
    }

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
        "misc/get_time.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(pbc_dir.join("include"))
        .include(&pbc_dir)
        .warnings(false)
        .opt_level(3)
        .flag_if_supported("-ffast-math")
        .flag_if_supported("-fomit-frame-pointer");

    // GMP include paths
    build.include("/opt/homebrew/include");
    build.include("/usr/local/include");

    for src in &pbc_srcs {
        let path = pbc_dir.join(src);
        if path.exists() {
            build.file(&path);
        } else {
            println!("cargo:warning=PBC source file not found: {}", path.display());
        }
    }

    build.compile("pbc_vendored");
    println!("cargo:warning=Built PBC from vendored source");
}
