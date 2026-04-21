pub mod commands;
pub mod crypto;
pub mod error;
pub mod ledger;
pub mod storage;

use storage::db::Database;
use std::sync::Mutex;
use tauri::Manager;

/// Shared application state accessible from Tauri commands.
pub struct AppState {
    pub db: Mutex<Database>,
    pub temp_files: Mutex<Vec<std::path::PathBuf>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize structured logging
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
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::broadcast::ensure_initialized,
            commands::broadcast::setup_broadcast,
            commands::broadcast::import_and_assign,
            commands::broadcast::generate_user_key,
            commands::broadcast::encrypt_broadcast,
            commands::broadcast::revoke_user,
            commands::broadcast::set_user_revoked,
            commands::broadcast::delete_user,
            commands::broadcast::download_user_key,
            commands::gpg::import_gpg_public_key,
            commands::gpg::list_gpg_keys,
            commands::decrypt::decrypt_content,
            commands::decrypt::decrypt_and_open,
            commands::decrypt::import_receiver_key,
            commands::decrypt::list_receiver_keys,
            commands::decrypt::set_active_receiver_key,
            commands::decrypt::delete_receiver_key,
            commands::decrypt::load_active_receiver_key,
            commands::file_crypto::encrypt_file,
            commands::file_crypto::decrypt_file,
            commands::file_crypto::save_temp_file,
            commands::file_crypto::get_file_info,
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
