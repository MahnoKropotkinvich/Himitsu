pub mod commands;
pub mod crypto;
pub mod error;
pub mod storage;
pub mod util;

use storage::db::Database;
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::Manager;

/// Shared application state accessible from Tauri commands.
pub struct AppState {
    pub db: Mutex<Database>,
    pub temp_files: Mutex<Vec<std::path::PathBuf>>,
    /// Live BGW broadcast systems, keyed by namespace ID.
    /// Loaded on demand from RocksDB.
    pub bgw: Mutex<HashMap<String, crypto::bgw::BgwSystem>>,
    /// Currently active namespace ID for the distributor UI.
    pub active_namespace: Mutex<Option<String>>,
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
        bgw: Mutex::new(HashMap::new()),
        active_namespace: Mutex::new(None),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_drag::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            // System
            commands::system::ensure_initialized,
            // Namespaces
            commands::namespace::create_namespace,
            commands::namespace::list_namespaces,
            commands::namespace::get_active_namespace,
            commands::namespace::set_active_namespace,
            commands::namespace::rename_namespace,
            commands::namespace::delete_namespace,
            // Subscribers (distributor-side)
            commands::subscribers::add_subscriber,
            commands::subscribers::import_subscriber_key,
            commands::subscribers::list_subscribers,
            commands::subscribers::set_subscriber_revoked,
            commands::subscribers::delete_subscriber,
            commands::subscribers::download_subscriber_key,
            commands::subscribers::export_subscriber_key,
            commands::subscribers::get_ledger_entries,
            commands::subscribers::search_ledger,
            // Receiver
            commands::receiver::import_key,
            commands::receiver::list_keys,
            commands::receiver::set_active_key,
            commands::receiver::delete_key,
            commands::receiver::get_active_key,
            // Encrypt
            commands::encrypt::encrypt_file,
            commands::encrypt::encrypt_folder,
            commands::encrypt::encrypt_content,
            // Decrypt
            commands::decrypt::decrypt_content,
            commands::decrypt::decrypt_file,
            commands::decrypt::decrypt_to_folder,
            // Files
            commands::files::get_file_info,
            commands::files::save_temp_file,
            commands::files::fetch_url,
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
