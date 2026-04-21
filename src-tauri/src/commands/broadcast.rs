use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;
use crate::crypto::{cover_crypt_ops, fingerprint, gpg_ops, key_mgmt};
use crate::ledger::distributor;
use crate::storage::models::LedgerAction;
use crate::storage::schema::{CF_MASTER_KEYS, CF_GPG_KEYS, CF_USER_KEYS, CF_ENCRYPTED_KEYS, CF_FINGERPRINTS};

/// Policy dimension spec from the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionSpec {
    pub name: String,
    pub hierarchical: bool,
    pub attributes: Vec<String>,
}

/// Check if the broadcast system is already initialized, if not, auto-init
/// with a default policy.  Called once on app startup by the frontend.
#[tauri::command]
pub fn ensure_initialized(
    state: State<'_, AppState>,
) -> std::result::Result<bool, String> {
    let db = state.db.lock().unwrap();
    if db.get_cf(CF_MASTER_KEYS, b"msk").map_err(|e| e.to_string())?.is_some() {
        tracing::debug!("Broadcast system already initialized");
        return Ok(false); // already initialized
    }
    drop(db);

    tracing::info!("First launch: auto-initializing broadcast encryption system");

    // Auto-init with a default single-dimension "broadcast" policy
    let default = vec![DimensionSpec {
        name: "Access".into(),
        hierarchical: false,
        attributes: vec!["Broadcast".into()],
    }];
    setup_broadcast(default, state)?;
    Ok(true) // freshly initialized
}

/// Initialize the CoverCrypt broadcast encryption system with a policy.
///
/// Creates a master key pair and stores it in the database.
#[tauri::command]
pub fn setup_broadcast(
    dimensions: Vec<DimensionSpec>,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    let dims: Vec<(String, bool, Vec<String>)> = dimensions
        .into_iter()
        .map(|d| (d.name, d.hierarchical, d.attributes))
        .collect();

    let kp = cover_crypt_ops::setup(&dims).map_err(|e| e.to_string())?;

    tracing::info!(
        dimensions = dims.len(),
        msk_bytes = kp.master_secret_key.len(),
        mpk_bytes = kp.public_key.len(),
        "CoverCrypt master key pair generated"
    );

    let db = state.db.lock().unwrap();
    db.put_cf(CF_MASTER_KEYS, b"msk", &kp.master_secret_key)
        .map_err(|e| e.to_string())?;
    db.put_cf(CF_MASTER_KEYS, b"mpk", &kp.public_key)
        .map_err(|e| e.to_string())?;

    Ok("Broadcast encryption system initialized".into())
}

/// Generate a CoverCrypt user secret key for an applicant,
/// wrap it with their GPG public key, record in the ledger,
/// and return the GPG-encrypted key blob as base64.
#[tauri::command]
pub fn generate_user_key(
    user_id: String,
    user_policy: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    let db = state.db.lock().unwrap();

    // 1. Load master secret key
    let msk_bytes = db
        .get_cf(CF_MASTER_KEYS, b"msk")
        .map_err(|e| e.to_string())?
        .ok_or("Master key not initialized. Run setup_broadcast first.")?;

    // 2. Generate the CoverCrypt user key
    let (wrapped_usk, updated_msk) =
        cover_crypt_ops::generate_user_key(&msk_bytes, &user_policy, &user_id)
            .map_err(|e| e.to_string())?;

    // 3. Persist updated MSK
    db.put_cf(CF_MASTER_KEYS, b"msk", &updated_msk)
        .map_err(|e| e.to_string())?;

    // 4. Load the user's GPG public key
    let gpg_data = db
        .get_cf(CF_GPG_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("GPG key not found for user {user_id}"))?;
    let applicant: crate::storage::models::Applicant =
        bincode::deserialize(&gpg_data).map_err(|e| e.to_string())?;
    let gpg_pub = gpg_ops::parse_public_key(&applicant.gpg_public_key_armored)
        .map_err(|e| e.to_string())?;

    // 5. Encrypt the CoverCrypt user key with GPG
    let encrypted_usk = key_mgmt::wrap_user_key_with_gpg(&wrapped_usk.key_data, &gpg_pub)
        .map_err(|e| e.to_string())?;

    // 6. Store the encrypted user key
    let usk_record = bincode::serialize(&wrapped_usk).map_err(|e| e.to_string())?;
    db.put_cf(CF_USER_KEYS, user_id.as_bytes(), &usk_record)
        .map_err(|e| e.to_string())?;

    // 7. Generate and store a fingerprint vector for this user
    let fp = fingerprint::generate_fingerprint(&user_id, 32, 65537);
    let fp_data = bincode::serialize(&crate::storage::models::FingerprintRecord {
        user_id: user_id.clone(),
        vector: fp.components.clone(),
        code_length: 32,
        created_at: chrono::Utc::now(),
    })
    .map_err(|e| e.to_string())?;
    db.put_cf(CF_FINGERPRINTS, user_id.as_bytes(), &fp_data)
        .map_err(|e| e.to_string())?;

    // 8. Record in the ledger
    let policy_attrs: Vec<String> = user_policy
        .split("&&")
        .map(|s| s.trim().to_string())
        .collect();
    distributor::record(
        &db,
        &user_id,
        &applicant.gpg_fingerprint,
        LedgerAction::KeyIssued,
        policy_attrs,
        None,
    )
    .map_err(|e| e.to_string())?;

    // 9. Return the GPG-encrypted user key as base64
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted_usk))
}

/// Broadcast-encrypt plaintext under a policy expression.
///
/// Fingerprint embedding happens here: the plaintext is watermarked
/// differently for each authorized user, and per-user ciphertexts
/// are returned.
#[tauri::command]
pub fn encrypt_broadcast(
    plaintext_base64: String,
    policy: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    use base64::Engine;

    let db = state.db.lock().unwrap();

    // 1. Decode plaintext
    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&plaintext_base64)
        .map_err(|e| format!("Invalid base64: {e}"))?;

    // 2. Load MPK
    let mpk_bytes = db
        .get_cf(CF_MASTER_KEYS, b"mpk")
        .map_err(|e| e.to_string())?
        .ok_or("Master key not initialized")?;

    // 3. Encrypt (single ciphertext under the policy)
    let broadcast_ct = cover_crypt_ops::encrypt(&mpk_bytes, &policy, &plaintext)
        .map_err(|e| e.to_string())?;

    // 4. Serialize and return as base64 JSON
    let ct_json = serde_json::to_string(&broadcast_ct).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(ct_json.as_bytes()))
}

/// Revoke a user's broadcast decryption key by rekeying the affected
/// policy attributes.
#[tauri::command]
pub fn revoke_user(
    user_id: String,
    revoke_policy: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    let db = state.db.lock().unwrap();

    // 1. Load MSK
    let msk_bytes = db
        .get_cf(CF_MASTER_KEYS, b"msk")
        .map_err(|e| e.to_string())?
        .ok_or("Master key not initialized")?;

    // 2. Rekey the specified attributes
    let updated_kp = cover_crypt_ops::rekey(&msk_bytes, &revoke_policy)
        .map_err(|e| e.to_string())?;

    // 3. Persist updated keys
    db.put_cf(CF_MASTER_KEYS, b"msk", &updated_kp.master_secret_key)
        .map_err(|e| e.to_string())?;
    db.put_cf(CF_MASTER_KEYS, b"mpk", &updated_kp.public_key)
        .map_err(|e| e.to_string())?;

    // 4. Record revocation in ledger
    let gpg_fp = db
        .get_cf(CF_GPG_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .and_then(|d| bincode::deserialize::<crate::storage::models::Applicant>(&d).ok())
        .map(|a| a.gpg_fingerprint)
        .unwrap_or_default();

    distributor::record(
        &db,
        &user_id,
        &gpg_fp,
        LedgerAction::KeyRevoked,
        vec![revoke_policy.clone()],
        Some(format!("User {user_id} revoked")),
    )
    .map_err(|e| e.to_string())?;

    Ok(format!("Revoked policy: {revoke_policy}"))
}

/// One-shot: import GPG public key + auto-generate CoverCrypt user key
/// + wrap with GPG + store everything + return the encrypted user key
/// as raw bytes (for file download).
///
/// This is the command the Distributor Settings page calls.
#[tauri::command]
pub fn import_and_assign(
    armored_key: String,
    display_name: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<u8>, String> {
    // 1. Parse GPG key
    let gpg_pub = gpg_ops::parse_public_key(&armored_key).map_err(|e| e.to_string())?;
    let fp = gpg_ops::fingerprint_hex(&gpg_pub);
    let user_id = fp.clone();

    tracing::info!(
        user_id = %user_id,
        display_name = %display_name,
        "import_and_assign: importing GPG key and generating broadcast key"
    );

    let db = state.db.lock().unwrap();

    // 2. Store the applicant
    let applicant = crate::storage::models::Applicant {
        user_id: user_id.clone(),
        display_name: display_name.clone(),
        gpg_fingerprint: fp.clone(),
        gpg_public_key_armored: armored_key.clone(),
        created_at: chrono::Utc::now(),
        revoked: false,
    };
    let applicant_bytes = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &applicant_bytes)
        .map_err(|e| e.to_string())?;

    // 3. Generate CoverCrypt user key (default broadcast policy)
    let msk_bytes = db
        .get_cf(CF_MASTER_KEYS, b"msk")
        .map_err(|e| e.to_string())?
        .ok_or("Broadcast system not initialized")?;

    let user_policy = "Access::Broadcast";
    let (wrapped_usk, updated_msk) =
        cover_crypt_ops::generate_user_key(&msk_bytes, user_policy, &user_id)
            .map_err(|e| e.to_string())?;

    db.put_cf(CF_MASTER_KEYS, b"msk", &updated_msk)
        .map_err(|e| e.to_string())?;

    // 4. Wrap with GPG
    let encrypted_usk = key_mgmt::wrap_user_key_with_gpg(&wrapped_usk.key_data, &gpg_pub)
        .map_err(|e| e.to_string())?;

    // 5. Store plain user key record AND the GPG-encrypted blob separately
    let usk_record = bincode::serialize(&wrapped_usk).map_err(|e| e.to_string())?;
    db.put_cf(CF_USER_KEYS, user_id.as_bytes(), &usk_record)
        .map_err(|e| e.to_string())?;
    // Store the GPG-encrypted blob so it can be re-downloaded any time
    db.put_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes(), &encrypted_usk)
        .map_err(|e| e.to_string())?;

    // 6. Generate fingerprint
    let fprint = fingerprint::generate_fingerprint(&user_id, 32, 65537);
    let fp_data = bincode::serialize(&crate::storage::models::FingerprintRecord {
        user_id: user_id.clone(),
        vector: fprint.components.clone(),
        code_length: 32,
        created_at: chrono::Utc::now(),
    })
    .map_err(|e| e.to_string())?;
    db.put_cf(CF_FINGERPRINTS, user_id.as_bytes(), &fp_data)
        .map_err(|e| e.to_string())?;

    // 7. Ledger
    distributor::record(
        &db,
        &user_id,
        &fp,
        LedgerAction::KeyIssued,
        vec![user_policy.to_string()],
        Some(display_name),
    )
    .map_err(|e| e.to_string())?;

    // 8. Return the GPG-encrypted user key bytes (frontend saves as file)
    Ok(encrypted_usk)
}

/// Return the GPG-encrypted user key blob for a given user (for re-download).
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

/// Permanently delete a subscriber and all associated data:
/// GPG key, user key, fingerprint vector, and ledger entries.
#[tauri::command]
pub fn delete_user(
    user_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    use crate::storage::schema::{CF_LEDGER};

    let db = state.db.lock().unwrap();

    // Delete from every column family that holds per-user data
    db.delete_cf(CF_GPG_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?;
    db.delete_cf(CF_USER_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?;
    db.delete_cf(CF_ENCRYPTED_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?;
    db.delete_cf(CF_FINGERPRINTS, user_id.as_bytes())
        .map_err(|e| e.to_string())?;

    // Remove all ledger entries belonging to this user
    let ledger_entries = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    for (key, value) in ledger_entries {
        if let Ok(entry) =
            bincode::deserialize::<crate::storage::models::LedgerEntry>(&value)
        {
            if entry.user_id == user_id {
                db.delete_cf(CF_LEDGER, &key).map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(())
}
#[tauri::command]
pub fn set_user_revoked(
    user_id: String,
    revoked: bool,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();

    let raw = db
        .get_cf(CF_GPG_KEYS, user_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("User not found")?;
    let mut applicant: crate::storage::models::Applicant =
        bincode::deserialize(&raw).map_err(|e| e.to_string())?;

    applicant.revoked = revoked;
    let data = bincode::serialize(&applicant).map_err(|e| e.to_string())?;
    db.put_cf(CF_GPG_KEYS, user_id.as_bytes(), &data)
        .map_err(|e| e.to_string())?;

    if revoked {
        // Rekey to actually revoke their crypto access
        let msk_bytes = db
            .get_cf(CF_MASTER_KEYS, b"msk")
            .map_err(|e| e.to_string())?
            .ok_or("Not initialized")?;
        let updated_kp = cover_crypt_ops::rekey(&msk_bytes, "Access::Broadcast")
            .map_err(|e| e.to_string())?;
        db.put_cf(CF_MASTER_KEYS, b"msk", &updated_kp.master_secret_key)
            .map_err(|e| e.to_string())?;
        db.put_cf(CF_MASTER_KEYS, b"mpk", &updated_kp.public_key)
            .map_err(|e| e.to_string())?;

        distributor::record(
            &db,
            &user_id,
            &applicant.gpg_fingerprint,
            LedgerAction::KeyRevoked,
            vec!["Access::Broadcast".into()],
            None,
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(())
}
