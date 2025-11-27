use anyhow::{Context, Result, anyhow};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};

pub struct Observable<T> {
    // A shared reference to the raw bytes
    inner: Arc<RwLock<Vec<u8>>>,
    // We pretend we hold a T for type safety, but we don't actually own a T
    _marker: PhantomData<T>,
}

impl<T: DeserializeOwned> Observable<T> {
    /// Get the current value from the store.
    /// This deserializes the latest bytes every time it is called.
    pub fn get(&self) -> Result<T> {
        let guard = self
            .inner
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock"))?;
        let obj = bincode::serde::decode_from_slice(&guard, bincode::config::standard())
            .map(|(t, _)| t)
            .context("Failed to deserialize object")?;
        Ok(obj)
    }
}

pub struct ObjectStore {
    path: PathBuf,
    storage: HashMap<String, Arc<RwLock<Vec<u8>>>>,
    cipher: Aes256Gcm,
}

impl ObjectStore {
    /// Create a new store instance.
    /// If the file exists, it loads it. If not, it starts empty.
    pub fn new(file_path: &str, password: &str) -> Result<Self> {
        let path = PathBuf::from(file_path);
        let key = ObjectStore::derive_key(password);
        let cipher = Aes256Gcm::new(&key);

        let storage = if path.exists() {
            let mut file = File::open(&path).context("Failed to open store file")?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            if buffer.is_empty() {
                HashMap::new()
            } else {
                // The file format is: [Nonce (12 bytes)] + [Encrypted Data]
                if buffer.len() < 12 {
                    return Err(anyhow!("File corrupted: too short to contain nonce"));
                }

                let (nonce_bytes, ciphertext) = buffer.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);

                let plaintext = cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("Decryption failed: {}", e))?;

                let raw_map: HashMap<String, Vec<u8>> =
                    bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())
                        .map(|(t, _)| t)
                        .context("Failed to decode store data")?;

                raw_map
                    .into_iter()
                    .map(|(k, v)| (k, Arc::new(RwLock::new(v))))
                    .collect()
            }
        } else {
            HashMap::new()
        };

        Ok(ObjectStore {
            path,
            storage,
            cipher,
        })
    }

    /// Save a generic object associated with a key.
    /// T: Serialize + Debug ensures the struct can be turned into bytes.
    pub fn insert<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        let new_bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
            .context("Failed to serialize object")?;

        // Check if the key already exists
        if let Some(shared_handle) = self.storage.get(key) {
            // UPDATE EXISTING: Write to the existing shared memory location.
            // Any Observable holding this handle will see the new data.
            let mut guard = shared_handle
                .write()
                .map_err(|_| anyhow!("Failed to acquire write lock"))?;
            *guard = new_bytes;
        } else {
            // INSERT NEW: Create a new shared memory location
            self.storage
                .insert(key.to_string(), Arc::new(RwLock::new(new_bytes)));
        }

        self.flush()
    }

    /// Retrieve an object by key. Returns a snapshot of the value.
    /// T: DeserializeOwned ensures the struct can be created from bytes.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        if let Some(shared_handle) = self.storage.get(key) {
            let guard = shared_handle
                .read()
                .map_err(|_| anyhow!("Failed to acquire read lock"))?;
            let obj = bincode::serde::decode_from_slice(&guard, bincode::config::standard())
                .map(|(t, _)| t)
                .context("Failed to deserialize object")?;
            Ok(Some(obj))
        } else {
            Ok(None)
        }
    }

    /// Returns a reactive Observer for the given key.
    /// If the key doesn't exist yet, this returns None.
    pub fn watch<T: DeserializeOwned>(&self, key: &str) -> Option<Observable<T>> {
        self.storage.get(key).map(|shared_handle| {
            Observable {
                inner: shared_handle.clone(), // Clone the Arc, not the data
                _marker: PhantomData,
            }
        })
    }

    /// Delete an object by key
    pub fn remove(&mut self, key: &str) -> Result<()> {
        // If anyone is holding an Observable to this key, their handle will still work, but it's
        // detached from the store.
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

        let mut raw_map: HashMap<String, Vec<u8>> = HashMap::new();
        for (k, v) in &self.storage {
            let bytes = v
                .read()
                .map_err(|_| anyhow!("Failed to read lock during flush"))?
                .clone();
            raw_map.insert(k.clone(), bytes);
        }

        let cleartext: Vec<u8> =
            bincode::serde::encode_to_vec(&raw_map, bincode::config::standard())?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, cleartext.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut final_data = nonce.to_vec();
        final_data.extend_from_slice(&ciphertext);

        file.write_all(&final_data)?;
        Ok(())
    }

    /// Helper to turn a string password into a 32-byte key
    fn derive_key(password: &str) -> aes_gcm::Key<Aes256Gcm> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        *aes_gcm::Key::<Aes256Gcm>::from_slice(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use serde::{Deserialize, Serialize};
    use std::fs;

    fn get_temp_path() -> String {
        let mut rng = rand::rng();
        let id: u32 = rng.random();
        let mut path = std::env::temp_dir();
        path.push(format!("cube_store_test_{}.cos", id));
        path.to_string_lossy().into_owned()
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct User {
        id: u32,
        name: String,
        active: bool,
    }

    #[test]
    fn test_basic_operations() -> Result<()> {
        let path = get_temp_path();
        let password = "secure_password";

        // Clean up previous run if exists (unlikely with random name)
        if std::path::Path::new(&path).exists() {
            fs::remove_file(&path)?;
        }

        {
            let mut store = ObjectStore::new(&path, password)?;

            store.insert("key1", &"value1".to_string())?;
            store.insert("key2", &42)?;

            let val1: Option<String> = store.get("key1")?;
            assert_eq!(val1, Some("value1".to_string()));

            let val2: Option<i32> = store.get("key2")?;
            assert_eq!(val2, Some(42));

            let val3: Option<String> = store.get("key3")?;
            assert_eq!(val3, None);

            store.remove("key1")?;
            let val1_after: Option<String> = store.get("key1")?;
            assert_eq!(val1_after, None);
        }

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_persistence() -> Result<()> {
        let path = get_temp_path();
        let password = "persistent_pass";

        let user = User {
            id: 1,
            name: "Alice".into(),
            active: true,
        };

        {
            let mut store = ObjectStore::new(&path, password)?;
            store.insert("user", &user)?;
        } // store dropped, flushed

        {
            let store = ObjectStore::new(&path, password)?;
            let retrieved: Option<User> = store.get("user")?;
            assert_eq!(retrieved, Some(user));
        }

        fs::remove_file(path).ok();
        Ok(())
    }

    #[test]
    fn test_wrong_password() -> Result<()> {
        let path = get_temp_path();
        let password = "correct_pass";

        {
            let mut store = ObjectStore::new(&path, password)?;
            store.insert("secret", &"data")?;
        }

        // Try opening with wrong password
        let result = ObjectStore::new(&path, "wrong_pass");
        assert!(result.is_err());

        fs::remove_file(path).ok();
        Ok(())
    }
}
