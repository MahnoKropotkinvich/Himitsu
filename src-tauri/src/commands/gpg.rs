use serde::Serialize;
use tauri::State;

use crate::AppState;
use crate::crypto::gpg_ops;
use crate::error::Result;
use crate::storage::models::Applicant;
use crate::storage::schema::CF_GPG_KEYS;

#[derive(Serialize)]
pub struct ImportResult {
    pub user_id: String,
    pub fingerprint: String,
    pub display_name: String,
}

/// Import an ASCII-armored GPG public key, store it, and return metadata.
#[tauri::command]
pub fn import_gpg_public_key(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<ImportResult, String> {
    let result = do_import(&armored_key, &display_name, &state);
    result.map_err(|e| e.to_string())
}

fn do_import(armored_key: &str, display_name: &str, state: &AppState) -> Result<ImportResult> {
    let key = gpg_ops::parse_public_key(armored_key)?;
    let fingerprint = gpg_ops::fingerprint_hex(&key);
    let user_id = fingerprint.clone();

    tracing::info!(
        user_id = %user_id,
        display_name = %display_name,
        "Importing GPG public key"
    );

    let applicant = Applicant {
        user_id: user_id.clone(),
        display_name: display_name.to_string(),
        gpg_fingerprint: fingerprint.clone(),
        gpg_public_key_armored: armored_key.to_string(),
        created_at: chrono::Utc::now(),
        revoked: false,
        bgw_index: u32::MAX, // placeholder — real index assigned by import_and_assign
    };

    let db = state.db.lock().unwrap();
    let value = bincode::serialize(&applicant)?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &value)?;

    tracing::info!(fingerprint = %fingerprint, "GPG key imported successfully");

    Ok(ImportResult {
        user_id,
        fingerprint,
        display_name: display_name.to_string(),
    })
}

/// List all imported GPG keys / applicants.
#[tauri::command]
pub fn list_gpg_keys(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<Applicant>, String> {
    let db = state.db.lock().unwrap();
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;

    let mut applicants = Vec::new();
    for (k, v) in &entries {
        match bincode::deserialize::<Applicant>(v) {
            Ok(a) => applicants.push(a),
            Err(e) => {
                tracing::warn!(
                    key = %hex::encode(k),
                    error = %e,
                    "Failed to deserialize applicant, skipping"
                );
            }
        }
    }
    tracing::debug!(
        total_entries = entries.len(),
        deserialized = applicants.len(),
        "list_gpg_keys"
    );
    Ok(applicants)
}
