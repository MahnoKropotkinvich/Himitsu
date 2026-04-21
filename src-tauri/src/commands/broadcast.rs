use tauri::State;

use crate::AppState;
use crate::crypto::{broadcast, fingerprint, gpg_ops, key_mgmt};
use crate::ledger::distributor;
use crate::storage::models::LedgerAction;
use crate::storage::schema::{CF_MASTER_KEYS, CF_GPG_KEYS, CF_USER_KEYS, CF_ENCRYPTED_KEYS, CF_FINGERPRINTS};

/// Check if the BGW broadcast system is initialized; if not, generate + persist.
/// If already persisted in DB, load from DB into memory.
#[tauri::command]
pub fn ensure_initialized(
    state: State<'_, AppState>,
) -> std::result::Result<bool, String> {
    let mut bgw_guard = state.bgw.lock().unwrap();
    if bgw_guard.is_some() {
        return Ok(false); // already in memory
    }

    let db = state.db.lock().unwrap();

    // Try loading from DB
    if let Some(data) = db.get_cf(CF_MASTER_KEYS, b"bgw_system").map_err(|e| e.to_string())? {
        tracing::info!("Loading BGW system from database");
        let sys = broadcast::BgwSystem::load(&data).map_err(|e| e.to_string())?;
        *bgw_guard = Some(sys);
        return Ok(false);
    }

    // First launch: generate + persist
    tracing::info!("First launch: generating BGW broadcast system (N={})", broadcast::MAX_USERS);
    let sys = broadcast::BgwSystem::generate().map_err(|e| e.to_string())?;
    let serialized = sys.serialize().map_err(|e| e.to_string())?;
    db.put_cf(CF_MASTER_KEYS, b"bgw_system", &serialized).map_err(|e| e.to_string())?;
    tracing::info!(bytes = serialized.len(), "BGW system persisted to database");
    *bgw_guard = Some(sys);
    Ok(true)
}

/// One-shot: import GPG public key + assign a BGW user slot + wrap private key with GPG.
#[tauri::command]
pub fn import_and_assign(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<u8>, String> {
    // 1. Parse GPG key
    let gpg_pub = gpg_ops::parse_public_key(&armored_key).map_err(|e| e.to_string())?;
    let fp = gpg_ops::fingerprint_hex(&gpg_pub);
    let user_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(user_id = %user_id, display_name = %display_name, "Importing subscriber");

    let db = state.db.lock().unwrap();

    // 2. Find next available user index
    let next_index = find_next_user_index(&db).map_err(|e| e.to_string())?;

    // 3. Store applicant
    let applicant = crate::storage::models::Applicant {
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

    // 4. Export BGW private key for this user index
    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;
    let user_key_bytes = bgw.export_user_key(next_index).map_err(|e| e.to_string())?;

    // 5. Bundle bgw_index + key bytes, then wrap with GPG
    let key_bundle = crate::storage::models::UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes.clone(),
    };
    let bundle_bytes = bincode::serialize(&key_bundle).map_err(|e| e.to_string())?;
    let encrypted_usk = key_mgmt::wrap_user_key_with_gpg(&bundle_bytes, &gpg_pub)
        .map_err(|e| e.to_string())?;

    // 6. Store user key metadata and encrypted blob
    let key_record = crate::storage::models::UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes,
    };
    let record_bytes = bincode::serialize(&key_record).map_err(|e| e.to_string())?;
    db.put_cf(CF_USER_KEYS, user_id.as_bytes(), &record_bytes)
        .map_err(|e| e.to_string())?;
    db.put_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes(), &encrypted_usk)
        .map_err(|e| e.to_string())?;

    // 7. Generate fingerprint
    let fprint = fingerprint::generate_fingerprint(&user_id, 32, 65537);
    let fp_data = bincode::serialize(&crate::storage::models::FingerprintRecord {
        user_id: user_id.clone(),
        vector: fprint.components.clone(),
        code_length: 32,
        created_at: chrono::Utc::now(),
    }).map_err(|e| e.to_string())?;
    db.put_cf(CF_FINGERPRINTS, user_id.as_bytes(), &fp_data)
        .map_err(|e| e.to_string())?;

    // 8. Ledger
    distributor::record(
        &db, &user_id, &fp,
        LedgerAction::KeyIssued,
        vec![format!("bgw_index:{}", next_index)],
        Some(display_name),
    ).map_err(|e| e.to_string())?;

    Ok(encrypted_usk)
}

/// Return the GPG-encrypted user key blob for re-download.
#[tauri::command]
pub fn download_user_key(
    user_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<u8>, String> {
    let db = state.db.lock().unwrap();
    db.get_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Encrypted key not found for this user".to_string())
}

/// Export a user's GPG-encrypted key to a file on disk.
#[tauri::command]
pub fn export_user_key(
    user_id: String,
    dest_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();
    let blob = db.get_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Encrypted key not found".to_string())?;
    std::fs::write(&dest_path, &blob)
        .map_err(|e| format!("Failed to write key file: {e}"))?;
    Ok(())
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
    let mut applicant: crate::storage::models::Applicant =
        bincode::deserialize(&raw).map_err(|e| e.to_string())?;

    applicant.revoked = revoked;
    let data = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &data)
        .map_err(|e| e.to_string())?;

    if revoked {
        distributor::record(
            &db, &user_id, &applicant.gpg_fingerprint,
            LedgerAction::KeyRevoked,
            vec![format!("bgw_index:{}", applicant.bgw_index)],
            None,
        ).map_err(|e| e.to_string())?;
    }

    tracing::info!(
        user_id = %user_id,
        revoked,
        "User revocation status changed"
    );

    Ok(())
}

/// Permanently delete a subscriber.
#[tauri::command]
pub fn delete_user(
    user_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    use crate::storage::schema::CF_LEDGER;

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
pub fn get_active_recipient_indices(db: &crate::storage::db::Database) -> std::result::Result<Vec<u32>, String> {
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;
    let mut indices = Vec::new();
    for (_k, v) in entries {
        if let Ok(a) = bincode::deserialize::<crate::storage::models::Applicant>(&v) {
            if !a.revoked {
                indices.push(a.bgw_index);
            }
        }
    }
    Ok(indices)
}

/// Find the next available BGW user index.
fn find_next_user_index(db: &crate::storage::db::Database) -> std::result::Result<u32, String> {
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;
    let mut used_indices = std::collections::HashSet::new();
    for (_k, v) in entries {
        if let Ok(a) = bincode::deserialize::<crate::storage::models::Applicant>(&v) {
            used_indices.insert(a.bgw_index);
        }
    }
    for i in 0..broadcast::MAX_USERS as u32 {
        if !used_indices.contains(&i) {
            return Ok(i);
        }
    }
    Err("All user slots are occupied (max 1000)".into())
}
