use thiserror::Error;

#[derive(Debug, Error)]
pub enum HimitsuError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("GPG error: {0}")]
    Gpg(String),

    #[error("Broadcast encryption error: {0}")]
    Broadcast(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Fingerprint error: {0}")]
    Fingerprint(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<rocksdb::Error> for HimitsuError {
    fn from(e: rocksdb::Error) -> Self {
        HimitsuError::Database(e.to_string())
    }
}

impl From<bincode::Error> for HimitsuError {
    fn from(e: bincode::Error) -> Self {
        HimitsuError::Serialization(e.to_string())
    }
}

// Make HimitsuError serializable for Tauri command returns
impl serde::Serialize for HimitsuError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, HimitsuError>;
