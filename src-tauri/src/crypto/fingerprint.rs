//! Arithmetic inner-product fingerprint embedding.
//!
//! This module handles the EMBEDDING side only.  Extraction and tracing
//! live in the separate `himitsu-trace` binary so that the main
//! application never ships with the ability to identify a decryptor.
//!
//! # Scheme overview
//!
//! 1. Each user is assigned a unique fingerprint vector **f_i** in F_p^n
//!    (generated via a collusion-resistant Tardos-like code).
//! 2. A random public vector **r** is generated per encryption session.
//! 3. The inner product <f_i, r> is computed and encoded into the least
//!    significant bits of the plaintext's redundant regions.
//! 4. Because each user gets a slightly different embedded value, the
//!    decrypted plaintext carries a unique watermark.
//!
//! The extraction counterpart reads those bits back out and matches
//! against the fingerprint database to find the leaker.

use num_bigint::BigInt;
use num_traits::Zero;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{HimitsuError, Result};

/// A user's fingerprint vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintVector {
    pub user_id: String,
    pub components: Vec<i64>,
}

/// Parameters for one encryption session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedSession {
    /// Public random vector (shared across all users in this session).
    pub r_vector: Vec<i64>,
    /// Prime modulus for inner-product arithmetic.
    pub modulus: i64,
}

/// Generate a fingerprint vector for a new user.
///
/// `code_length` controls the number of components (higher = more
/// collusion resistance, but more bits needed in the plaintext).
pub fn generate_fingerprint(user_id: &str, code_length: usize, modulus: i64) -> FingerprintVector {
    let mut rng = rand::thread_rng();
    let components: Vec<i64> = (0..code_length)
        .map(|_| rng.gen_range(0..modulus))
        .collect();

    FingerprintVector {
        user_id: user_id.to_string(),
        components,
    }
}

/// Create a new embedding session (generates the public random vector).
pub fn new_session(code_length: usize, modulus: i64) -> EmbedSession {
    let mut rng = rand::thread_rng();
    let r_vector: Vec<i64> = (0..code_length)
        .map(|_| rng.gen_range(0..modulus))
        .collect();
    EmbedSession { r_vector, modulus }
}

/// Compute the inner product <fingerprint, r> mod p.
pub fn inner_product(fp: &FingerprintVector, session: &EmbedSession) -> Result<i64> {
    if fp.components.len() != session.r_vector.len() {
        return Err(HimitsuError::Fingerprint(
            "Vector length mismatch".into(),
        ));
    }

    let mut acc = BigInt::zero();
    for (a, b) in fp.components.iter().zip(session.r_vector.iter()) {
        acc += BigInt::from(*a) * BigInt::from(*b);
    }
    let modulus = BigInt::from(session.modulus);
    let result = acc % &modulus;
    // Ensure non-negative
    let result = if result < BigInt::zero() {
        result + modulus
    } else {
        result
    };

    Ok(result
        .try_into()
        .map_err(|_| HimitsuError::Fingerprint("Inner product overflow".into()))?)
}

/// Embed a fingerprint value into the plaintext.
///
/// Modifies the least-significant bits of bytes at regular intervals.
/// Returns the watermarked plaintext.  The number of bits used is
/// ceil(log2(modulus)).
pub fn embed_in_plaintext(
    plaintext: &[u8],
    fingerprint_value: i64,
    session: &EmbedSession,
) -> Result<Vec<u8>> {
    let bits_needed = (session.modulus as f64).log2().ceil() as usize;
    if bits_needed == 0 {
        return Err(HimitsuError::Fingerprint("Modulus too small".into()));
    }

    // We need `bits_needed` bytes of headroom at minimum
    if plaintext.len() < bits_needed + 16 {
        return Err(HimitsuError::Fingerprint(
            "Plaintext too short for fingerprint embedding".into(),
        ));
    }

    let mut output = plaintext.to_vec();

    // Spread the fingerprint bits across the plaintext at regular intervals
    let stride = output.len() / (bits_needed + 1);
    let stride = stride.max(1);

    let mut val = fingerprint_value;
    for i in 0..bits_needed {
        let pos = ((i + 1) * stride).min(output.len() - 1);
        // Clear LSB and set to our bit
        output[pos] = (output[pos] & 0xFE) | ((val & 1) as u8);
        val >>= 1;
    }

    Ok(output)
}
