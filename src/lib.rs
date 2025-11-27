use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

pub struct ObjectStore {
    path: PathBuf,
    storage: HashMap<String, Vec<u8>>,
}

impl ObjectStore {
    /// Create a new store instance.
    /// If the file exists, it loads it. If not, it starts empty.
    pub fn new(file_path: &str) -> Result<Self> {
        let path = PathBuf::from(file_path);

        let storage = if path.exists() {
            let mut file = File::open(&path).context("Failed to open store file")?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            if buffer.is_empty() {
                HashMap::new()
            } else {
                bincode::serde::decode_from_slice(&buffer, bincode::config::standard())
                    .map(|(t, _)| t)
                    .context("Failed to decode store data")?
            }
        } else {
            HashMap::new()
        };

        Ok(ObjectStore { path, storage })
    }

    /// Save a generic object associated with a key.
    /// T: Serialize + Debug ensures the struct can be turned into bytes.
    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
            .context("Failed to serialize object")?;

        self.storage.insert(key.to_string(), bytes);

        self.flush()
    }

    /// Retrieve an object by key.
    /// T: DeserializeOwned ensures the struct can be created from bytes.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        match self.storage.get(key) {
            Some(bytes) => {
                let obj = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                    .map(|(t, _)| t)
                    .context("Failed to deserialize object")?;
                Ok(Some(obj))
            }
            None => Ok(None),
        }
    }

    /// Delete an object by key
    pub fn remove(&mut self, key: &str) -> Result<()> {
        self.storage.remove(key);
        self.flush()
    }

    /// Internal function to write the entire memory map to disk
    fn flush(&self) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // Overwrite existing file
            .open(&self.path)?;

        let encoded: Vec<u8> =
            bincode::serde::encode_to_vec(&self.storage, bincode::config::standard())?;
        file.write_all(&encoded)?;
        Ok(())
    }
}
