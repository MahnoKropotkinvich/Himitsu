//! Extract a fingerprint value from a leaked plaintext file.
//!
//! Reverses the embedding performed by the main Himitsu application's
//! `crypto::fingerprint::embed_in_plaintext` function.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct EmbedSession {
    pub r_vector: Vec<i64>,
    pub modulus: i64,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractedFingerprint {
    pub value: i64,
    pub modulus: i64,
    pub source_file: String,
}

pub fn run(input: &Path, session_path: &Path, output: &Path) -> Result<(), String> {
    // Load the leaked plaintext
    let plaintext = std::fs::read(input)
        .map_err(|e| format!("Failed to read input file: {e}"))?;

    // Load session metadata
    let session_json = std::fs::read_to_string(session_path)
        .map_err(|e| format!("Failed to read session file: {e}"))?;
    let session: EmbedSession = serde_json::from_str(&session_json)
        .map_err(|e| format!("Failed to parse session JSON: {e}"))?;

    // Extract the fingerprint bits from the plaintext LSBs
    let bits_needed = (session.modulus as f64).log2().ceil() as usize;
    if plaintext.len() < bits_needed + 16 {
        return Err("Plaintext too short to contain a fingerprint".into());
    }

    let stride = plaintext.len() / (bits_needed + 1);
    let stride = stride.max(1);

    let mut value: i64 = 0;
    for i in (0..bits_needed).rev() {
        let pos = ((i + 1) * stride).min(plaintext.len() - 1);
        let bit = (plaintext[pos] & 1) as i64;
        value = (value << 1) | bit;
    }

    let result = ExtractedFingerprint {
        value,
        modulus: session.modulus,
        source_file: input.display().to_string(),
    };

    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Failed to serialize result: {e}"))?;
    std::fs::write(output, &json)
        .map_err(|e| format!("Failed to write output: {e}"))?;

    println!("Extracted fingerprint value: {}", result.value);
    println!("Written to: {}", output.display());

    Ok(())
}
