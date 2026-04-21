pub mod commands;
pub mod crypto;
pub mod error;
pub mod storage;
pub mod util;

use storage::db::Database;
use std::sync::Mutex;
use tauri::Manager;

/// Shared application state accessible from Tauri commands.
pub struct AppState {
    pub db: Mutex<Database>,
    pub temp_files: Mutex<Vec<std::path::PathBuf>>,
    /// Live BGW broadcast encryption system (kept in memory).
    pub bgw: Mutex<Option<crypto::bgw::BgwSystem>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "himitsu=debug,himitsu_lib=debug".into()),
        )
        .with_target(true)
        .init();

    tracing::info!("Himitsu starting up");

    let db = Database::open_default()
        .expect("Failed to open RocksDB database");

    tracing::info!(path = %db.path.display(), "Database opened");

    let state = AppState {
        db: Mutex::new(db),
        temp_files: Mutex::new(Vec::new()),
        bgw: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            // System
            commands::system::ensure_initialized,
            // Subscribers
            commands::subscribers::import_and_assign,
            commands::subscribers::import_gpg_public_key,
            commands::subscribers::list_gpg_keys,
            commands::subscribers::set_user_revoked,
            commands::subscribers::delete_user,
            // Keys
            commands::keys::download_user_key,
            commands::keys::export_user_key,
            commands::keys::import_receiver_key,
            commands::keys::list_receiver_keys,
            commands::keys::set_active_receiver_key,
            commands::keys::delete_receiver_key,
            commands::keys::load_active_receiver_key,
            // Encrypt
            commands::encrypt::encrypt_file,
            commands::encrypt::encrypt_folder,
            // Decrypt
            commands::decrypt::decrypt_content,
            commands::decrypt::decrypt_and_open,
            commands::decrypt::decrypt_file,
            commands::decrypt::decrypt_to_folder,
            // Files
            commands::files::get_file_info,
            commands::files::save_temp_file,
            // Ledger
            commands::ledger::get_ledger_entries,
            commands::ledger::search_ledger,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<AppState>() {
                    if let Ok(files) = state.temp_files.lock() {
                        let count = files.len();
                        for path in files.iter() {
                            if let Ok(meta) = std::fs::metadata(path) {
                                let zeros = vec![0u8; meta.len() as usize];
                                let _ = std::fs::write(path, &zeros);
                            }
                            let _ = std::fs::remove_file(path);
                        }
                        if count > 0 {
                            tracing::info!(count, "Cleaned up temporary decrypted files");
                        }
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
