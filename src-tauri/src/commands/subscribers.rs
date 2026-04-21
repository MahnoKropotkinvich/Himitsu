//! Subscriber management: import, revoke, delete, list.

use tauri::State;

use crate::AppState;
use crate::crypto::{bgw, fingerprint, gpg};
use crate::storage::db::Database;
use crate::storage::models::{Applicant, ImportResult, UserKeyRecord, FingerprintRecord, LedgerAction};
use crate::storage::schema::*;

/// Import a GPG public key, assign a BGW slot, wrap the private key with GPG,
/// and return the encrypted key blob.
#[tauri::command]
pub fn import_and_assign(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<u8>, String> {
    let gpg_pub = gpg::parse_public_key(&armored_key).map_err(|e| e.to_string())?;
    let fp = gpg::fingerprint_hex(&gpg_pub);
    let user_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(user_id = %user_id, display_name = %display_name, "Importing subscriber");

    let db = state.db.lock().unwrap();

    let next_index = find_next_user_index(&db).map_err(|e| e.to_string())?;

    let applicant = Applicant {
        user_id: user_id.clone(),
        display_name: display_name.clone(),
        gpg_fingerprint: fp.clone(),
        gpg_public_key_armored: armored_key.clone(),
        created_at: chrono::Utc::now(),
        revoked: false,
        bgw_index: next_index,
    };
    let applicant_bytes = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &applicant_bytes)
        .map_err(|e| e.to_string())?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;
    let user_key_bytes = bgw_sys.export_user_key(next_index).map_err(|e| e.to_string())?;

    let key_bundle = UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes.clone(),
    };
    let bundle_bytes = bincode::serialize(&key_bundle).map_err(|e| e.to_string())?;
    let encrypted_usk = gpg::encrypt_to_key(&bundle_bytes, &gpg_pub)
        .map_err(|e| e.to_string())?;

    let key_record = UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes,
    };
    let record_bytes = bincode::serialize(&key_record).map_err(|e| e.to_string())?;
    db.put_cf(CF_USER_KEYS, user_id.as_bytes(), &record_bytes)
        .map_err(|e| e.to_string())?;
    db.put_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes(), &encrypted_usk)
        .map_err(|e| e.to_string())?;

    let fprint = fingerprint::generate_fingerprint(&user_id, 32, 65537);
    let fp_data = bincode::serialize(&FingerprintRecord {
        user_id: user_id.clone(),
        vector: fprint.components.clone(),
        code_length: 32,
        created_at: chrono::Utc::now(),
    }).map_err(|e| e.to_string())?;
    db.put_cf(CF_FINGERPRINTS, user_id.as_bytes(), &fp_data)
        .map_err(|e| e.to_string())?;

    super::ledger::record(
        &db, &user_id, &fp,
        LedgerAction::KeyIssued,
        vec![format!("bgw_index:{}", next_index)],
        Some(display_name),
    ).map_err(|e| e.to_string())?;

    Ok(encrypted_usk)
}

/// Import an ASCII-armored GPG public key only (no BGW slot assignment).
#[tauri::command]
pub fn import_gpg_public_key(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<ImportResult, String> {
    let key = gpg::parse_public_key(&armored_key).map_err(|e| e.to_string())?;
    let fingerprint = gpg::fingerprint_hex(&key);
    let user_id = fingerprint.clone();

    tracing::info!(user_id = %user_id, display_name = %display_name, "Importing GPG public key");

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
    let value = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &value).map_err(|e| e.to_string())?;

    tracing::info!(fingerprint = %fingerprint, "GPG key imported");

    Ok(ImportResult {
        user_id,
        fingerprint,
        display_name: display_name.to_string(),
    })
}

/// List all imported subscribers.
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
    Ok(applicants)
}

/// Toggle revoked status. Revoked users are excluded from the
/// recipient set at encryption time.
#[tauri::command]
pub fn set_user_revoked(
    user_id: String,
    revoked: bool,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();
    let raw = db.get_cf(CF_GPG_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("User not found")?;
    let mut applicant: Applicant =
        bincode::deserialize(&raw).map_err(|e| e.to_string())?;

    applicant.revoked = revoked;
    let data = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &data)
        .map_err(|e| e.to_string())?;

    if revoked {
        super::ledger::record(
            &db, &user_id, &applicant.gpg_fingerprint,
            LedgerAction::KeyRevoked,
            vec![format!("bgw_index:{}", applicant.bgw_index)],
            None,
        ).map_err(|e| e.to_string())?;
    }

    tracing::info!(user_id = %user_id, revoked, "User revocation status changed");

    Ok(())
}

/// Permanently delete a subscriber and all associated data.
#[tauri::command]
pub fn delete_user(
    user_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();
    db.delete_cf(CF_GPG_KEYS, user_id.as_bytes()).map_err(|e| e.to_string())?;
    db.delete_cf(CF_USER_KEYS, user_id.as_bytes()).map_err(|e| e.to_string())?;
    db.delete_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes()).map_err(|e| e.to_string())?;
    db.delete_cf(CF_FINGERPRINTS, user_id.as_bytes()).map_err(|e| e.to_string())?;

    let ledger_entries = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    for (key, value) in ledger_entries {
        if let Ok(entry) = bincode::deserialize::<crate::storage::models::LedgerEntry>(&value) {
            if entry.user_id == user_id {
                db.delete_cf(CF_LEDGER, &key).map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(())
}

/// Get the list of non-revoked user BGW indices for encryption.
pub fn get_active_recipient_indices(db: &Database) -> std::result::Result<Vec<u32>, String> {
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;
    let mut indices = Vec::new();
    for (_k, v) in entries {
        if let Ok(a) = bincode::deserialize::<Applicant>(&v) {
            if !a.revoked {
                indices.push(a.bgw_index);
            }
        }
    }
    Ok(indices)
}

/// Find the next available BGW user index.
fn find_next_user_index(db: &Database) -> std::result::Result<u32, String> {
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;
    let mut used_indices = std::collections::HashSet::new();
    for (_k, v) in entries {
        if let Ok(a) = bincode::deserialize::<Applicant>(&v) {
            used_indices.insert(a.bgw_index);
        }
    }
    for i in 0..bgw::MAX_USERS as u32 {
        if !used_indices.contains(&i) {
            return Ok(i);
        }
    }
    Err("All user slots are occupied (max 1000)".into())
}
