//! Subscriber management: import, revoke, delete, list.

use tauri::State;

use crate::AppState;
use crate::crypto::{fingerprint, gpg};
use crate::storage::db::Database;
use crate::storage::models::{Applicant, ImportResult, UserKeyRecord, FingerprintRecord, LedgerAction, LedgerEntry, KeySlot, SlotState};
use crate::storage::schema::*;

/// Import a GPG public key, assign a BGW slot, wrap the private key with GPG,
/// and return the encrypted key blob.
#[tauri::command]
pub fn add_subscriber(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<u8>, String> {
    let gpg_pub = gpg::parse_public_key(&armored_key).map_err(|e| e.to_string())?;
    let fp = gpg::fingerprint_hex(&gpg_pub);
    let user_id = uuid::Uuid::new_v4().to_string();

    let namespace_id = super::namespace::require_active_namespace(&state)?;

    tracing::info!(user_id = %user_id, display_name = %display_name, namespace = %namespace_id, "Importing subscriber");

    let db = state.db.lock().unwrap();

    // Find an available slot in this namespace
    let next_index = find_available_slot(&db, &namespace_id)?;

    let applicant = Applicant {
        user_id: user_id.clone(),
        display_name: display_name.clone(),
        gpg_fingerprint: fp.clone(),
        gpg_public_key_armored: armored_key.clone(),
        created_at: chrono::Utc::now(),
        revoked: false,
        bgw_index: next_index,
        namespace_id: namespace_id.clone(),
    };
    let applicant_bytes = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &applicant_bytes)
        .map_err(|e| e.to_string())?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.get(&namespace_id)
        .ok_or("BGW system not loaded for this namespace")?;
    let user_key_bytes = bgw_sys.export_user_key(next_index).map_err(|e| e.to_string())?;
    let pk_bytes = bgw_sys.export_public_key().map_err(|e| e.to_string())?;

    let key_bundle = UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes.clone(),
        pk_data: pk_bytes.clone(),
    };
    let bundle_bytes = bincode::serialize(&key_bundle).map_err(|e| e.to_string())?;
    let encrypted_usk = gpg::encrypt_to_key(&bundle_bytes, &gpg_pub)
        .map_err(|e| e.to_string())?;

    let key_record = UserKeyRecord {
        user_id: user_id.clone(),
        bgw_index: next_index,
        key_data: user_key_bytes,
        pk_data: pk_bytes,
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

    record_ledger(
        &db, &user_id, &fp,
        LedgerAction::KeyIssued,
        vec![format!("bgw_index:{}", next_index), format!("namespace:{}", namespace_id)],
        Some(display_name),
    ).map_err(|e| e.to_string())?;

    // Mark slot as Assigned
    update_slot_state(&db, &namespace_id, next_index, SlotState::Assigned, Some(&user_id))?;

    Ok(encrypted_usk)
}

/// Import an ASCII-armored GPG public key only (no BGW slot assignment).
#[tauri::command]
pub fn import_subscriber_key(
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
        namespace_id: String::new(), // placeholder
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

/// List subscribers belonging to the active namespace.
#[tauri::command]
pub fn list_subscribers(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<Applicant>, String> {
    let namespace_id = super::namespace::require_active_namespace(&state)?;
    let db = state.db.lock().unwrap();
    let entries = db.iter_cf(CF_GPG_KEYS).map_err(|e| e.to_string())?;

    let mut applicants = Vec::new();
    for (k, v) in &entries {
        match bincode::deserialize::<Applicant>(v) {
            Ok(a) => {
                if a.namespace_id == namespace_id {
                    applicants.push(a);
                }
            }
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

/// Toggle revoked status. Revoked slots are excluded from the
/// recipient set at encryption time — revoked users cannot decrypt
/// new content. Restoring re-includes the slot.
#[tauri::command]
pub fn set_subscriber_revoked(
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

    // Update slot state: Revoked ↔ Assigned
    if !applicant.namespace_id.is_empty() {
        let new_state = if revoked { SlotState::Revoked } else { SlotState::Assigned };
        update_slot_state(
            &db,
            &applicant.namespace_id,
            applicant.bgw_index,
            new_state,
            Some(&user_id),
        )?;
    }

    if revoked {
        record_ledger(
            &db, &user_id, &applicant.gpg_fingerprint,
            LedgerAction::KeyRevoked,
            vec![format!("bgw_index:{}", applicant.bgw_index)],
            None,
        ).map_err(|e| e.to_string())?;
    }

    tracing::info!(user_id = %user_id, revoked, "User revocation status changed");

    Ok(())
}

/// Permanently delete a subscriber and destroy their key slot.
///
/// The slot is marked `Deleted` — it will never be reassigned and the
/// namespace's available seat count does NOT increase.
#[tauri::command]
pub fn delete_subscriber(
    user_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();

    // Read applicant first to get namespace_id + bgw_index
    if let Some(raw) = db.get_cf(CF_GPG_KEYS, user_id.as_bytes()).map_err(|e| e.to_string())? {
        if let Ok(applicant) = bincode::deserialize::<Applicant>(&raw) {
            if !applicant.namespace_id.is_empty() {
                update_slot_state(
                    &db,
                    &applicant.namespace_id,
                    applicant.bgw_index,
                    SlotState::Deleted,
                    None,
                )?;
            }
        }
    }

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

/// Find the first available slot in a namespace.
fn find_available_slot(db: &Database, namespace_id: &str) -> std::result::Result<u32, String> {
    let prefix = format!("{}:", namespace_id);
    let slots = db.prefix_iter_cf(CF_KEY_SLOTS, prefix.as_bytes())
        .map_err(|e| e.to_string())?;

    for (_k, v) in slots {
        if let Ok(slot) = bincode::deserialize::<KeySlot>(&v) {
            if slot.state == SlotState::Available {
                return Ok(slot.index);
            }
        }
    }
    Err("No available seats remaining in this namespace".into())
}

/// Update a key slot's state in the database.
fn update_slot_state(
    db: &Database,
    namespace_id: &str,
    index: u32,
    new_state: SlotState,
    user_id: Option<&str>,
) -> std::result::Result<(), String> {
    let slot_key = format!("{}:{:04}", namespace_id, index);
    let raw = db.get_cf(CF_KEY_SLOTS, slot_key.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("Slot not found")?;
    let mut slot: KeySlot = bincode::deserialize(&raw).map_err(|e| e.to_string())?;

    slot.state = new_state;
    if let Some(uid) = user_id {
        slot.user_id = Some(uid.to_string());
        if slot.assigned_at.is_none() {
            slot.assigned_at = Some(chrono::Utc::now());
        }
    }

    let data = bincode::serialize(&slot).map_err(|e| e.to_string())?;
    db.put_cf(CF_KEY_SLOTS, slot_key.as_bytes(), &data)
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ledger: recording and querying distribution events
// ---------------------------------------------------------------------------

/// Record a distribution event in the ledger.
pub fn record_ledger(
    db: &Database,
    user_id: &str,
    gpg_fingerprint: &str,
    action: LedgerAction,
    policy_attributes: Vec<String>,
    notes: Option<String>,
) -> std::result::Result<String, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let entry = LedgerEntry {
        id: id.clone(),
        user_id: user_id.to_string(),
        gpg_fingerprint: gpg_fingerprint.to_string(),
        action,
        timestamp: chrono::Utc::now(),
        policy_attributes,
        notes,
    };

    let value = bincode::serialize(&entry).map_err(|e| e.to_string())?;
    let key = format!("{}:{}", entry.timestamp.timestamp_millis(), user_id);
    db.put_cf(CF_LEDGER, key.as_bytes(), &value)
        .map_err(|e| e.to_string())?;

    Ok(id)
}

/// Retrieve all ledger entries (newest first).
#[tauri::command]
pub fn get_ledger_entries(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    let raw = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    let mut entries: Vec<LedgerEntry> = raw
        .iter()
        .filter_map(|(_k, v)| bincode::deserialize(v).ok())
        .collect();
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

/// Search ledger entries by user_id or fingerprint substring.
#[tauri::command]
pub fn search_ledger(
    query: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    let raw = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    let mut entries: Vec<LedgerEntry> = raw
        .iter()
        .filter_map(|(_k, v)| bincode::deserialize(v).ok())
        .collect();
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let query_lower = query.to_lowercase();
    Ok(entries
        .into_iter()
        .filter(|e| {
            e.user_id.to_lowercase().contains(&query_lower)
                || e.gpg_fingerprint.to_lowercase().contains(&query_lower)
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Distributor-side key export
// ---------------------------------------------------------------------------

/// Return the GPG-encrypted user key blob for re-download.
#[tauri::command]
pub fn download_subscriber_key(
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
pub fn export_subscriber_key(
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
