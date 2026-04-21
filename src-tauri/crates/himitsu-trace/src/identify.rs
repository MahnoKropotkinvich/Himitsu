//! Identify a traitor by matching an extracted fingerprint value
//! against the fingerprint database.

use serde::{Deserialize, Serialize};
use std::path::Path;
use num_bigint::BigInt;
use num_traits::Zero;

use super::extract::{EmbedSession, ExtractedFingerprint};

#[derive(Serialize, Deserialize, Debug)]
pub struct FingerprintRecord {
    pub user_id: String,
    pub vector: Vec<i64>,
    pub code_length: usize,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn run(extracted_path: &Path, db_path: &Path) -> Result<(), String> {
    // Load extracted fingerprint
    let fp_json = std::fs::read_to_string(extracted_path)
        .map_err(|e| format!("Failed to read extracted fingerprint: {e}"))?;
    let extracted: ExtractedFingerprint = serde_json::from_str(&fp_json)
        .map_err(|e| format!("Failed to parse extracted fingerprint: {e}"))?;

    // Open the Himitsu database (read-only)
    let db = open_db_readonly(db_path)?;

    // Read all fingerprint records
    let fingerprints = read_fingerprints(&db)?;

    if fingerprints.is_empty() {
        println!("No fingerprint records found in database.");
        return Ok(());
    }

    println!("Searching {} fingerprint records...", fingerprints.len());
    println!("Target value: {} (mod {})", extracted.value, extracted.modulus);

    // NOTE: to fully match, we'd also need the session's r_vector.
    // For now this tool reports all user IDs for manual investigation.
    // In a real deployment, the session r_vector would be stored alongside
    // the ciphertext, and the inner product <f_i, r> would be computed
    // for each user and compared against the extracted value.

    println!("\nRegistered users in fingerprint database:");
    for fp in &fingerprints {
        println!("  - {} (vector length: {})", fp.user_id, fp.vector.len());
    }

    println!("\nTo complete identification, supply the session r_vector");
    println!("and compute <f_i, r> mod p for each user.");

    Ok(())
}

fn open_db_readonly(path: &Path) -> Result<rocksdb::DB, String> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);

    // Open with known CFs
    let cf_names = ["fingerprints", "ledger", "gpg_keys", "cc_master",
                     "user_keys", "encrypted_keys", "ciphertexts", "receiver", "config"];
    let cfs: Vec<rocksdb::ColumnFamilyDescriptor> = cf_names
        .iter()
        .map(|n| rocksdb::ColumnFamilyDescriptor::new(*n, rocksdb::Options::default()))
        .collect();

    rocksdb::DB::open_cf_descriptors_read_only(&opts, path, cfs, false)
        .map_err(|e| format!("Failed to open database: {e}"))
}

fn read_fingerprints(db: &rocksdb::DB) -> Result<Vec<FingerprintRecord>, String> {
    let cf = db.cf_handle("fingerprints")
        .ok_or("fingerprints column family not found")?;

    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    let mut records = Vec::new();
    for item in iter {
        let (_k, v) = item.map_err(|e| format!("DB iteration error: {e}"))?;
        if let Ok(record) = bincode::deserialize::<FingerprintRecord>(&v) {
            records.push(record);
        }
    }
    Ok(records)
}
