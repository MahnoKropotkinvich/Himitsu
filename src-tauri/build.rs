fn main() {
    tauri_build::build();

    // On MSVC-host runners targeting x86_64-pc-windows-gnu, tauri-winres
    // compiles the Windows resource (.rc) with the MSVC resource compiler
    // (rc.exe → lib.exe), producing a COFF .lib that MinGW ld cannot link.
    // Fix: re-compile the resource with windres, overwriting resource.lib.
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "windows" && target_env == "gnu" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let lib_path = std::path::PathBuf::from(&out_dir).join("resource.lib");

        // Only fix if tauri-build actually produced a resource.lib
        if lib_path.exists() {
            // tauri-winres writes the .rc source next to the .lib
            let rc_path = std::path::PathBuf::from(&out_dir).join("resource.rc");
            if rc_path.exists() {
                let status = std::process::Command::new("windres")
                    .arg(rc_path.to_str().unwrap())
                    .args(["-O", "coff"])
                    .arg("-o")
                    .arg(lib_path.to_str().unwrap())
                    .status()
                    .expect("windres not found – ensure MSYS2 MinGW binutils is in PATH");
                assert!(status.success(), "windres failed to re-compile resource");
            }
        }
    }
}
