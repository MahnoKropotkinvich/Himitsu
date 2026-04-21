use rocksdb::{Options, DB, ColumnFamilyDescriptor};
use std::path::PathBuf;

use crate::error::{HimitsuError, Result};
use super::schema::ALL_CFS;

/// Thin wrapper around RocksDB providing column-family-aware access.
pub struct Database {
    pub inner: DB,
    pub path: PathBuf,
}

impl Database {
    /// Open (or create) the database at the platform-specific data directory.
    pub fn open_default() -> Result<Self> {
        let base = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("himitsu")
            .join("db");

        std::fs::create_dir_all(&base)?;
        Self::open(&base)
    }

    pub fn open(path: &std::path::Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // RocksDB ALWAYS has a "default" CF. It MUST be included
        // in open_cf_descriptors, otherwise cf_handle lookups return
        // wrong handles due to index mismatch.
        let mut cf_descriptors: Vec<ColumnFamilyDescriptor> = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
        ];
        for name in ALL_CFS {
            cf_descriptors.push(ColumnFamilyDescriptor::new(*name, Options::default()));
        }

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| HimitsuError::Database(e.to_string()))?;

        Ok(Self {
            inner: db,
            path: path.to_path_buf(),
        })
    }

    /// Put a key-value pair into a specific column family.
    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| HimitsuError::Database(format!("CF {} not found", cf_name)))?;
        self.inner.put_cf(&cf, key, value)?;
        Ok(())
    }

    /// Get a value from a specific column family.
    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| HimitsuError::Database(format!("CF {} not found", cf_name)))?;
        Ok(self.inner.get_cf(&cf, key)?)
    }

    /// Delete a key from a specific column family.
    pub fn delete_cf(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| HimitsuError::Database(format!("CF {} not found", cf_name)))?;
        self.inner.delete_cf(&cf, key)?;
        Ok(())
    }

    /// Iterate over all entries in a column family.
    pub fn iter_cf(&self, cf_name: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| HimitsuError::Database(format!("CF {} not found", cf_name)))?;
        let iter = self.inner.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| HimitsuError::Database(e.to_string()))?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    /// Count entries in a column family (for debugging).
    pub fn count_cf(&self, cf_name: &str) -> Result<usize> {
        Ok(self.iter_cf(cf_name)?.len())
    }
}
