use anyhow::{Context, Result, anyhow};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[cfg(target_os = "macos")]
use std::process::Command;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hex::encode as hex_encode;
use sha2::{Digest, Sha256};

/// Generates a deterministic password tied to the current machine and OS.
/// It prefers platform-specific identifiers (machine-id, hardware UUID, MachineGuid)
/// and falls back to host/user metadata before hashing everything into a stable hex string.
pub fn machine_password() -> Result<String> {
    let mut components = Vec::new();

    if let Some(primary) = platform_unique_identifier() {
        components.push(primary);
    }

    // Host- and user-scoped values help differentiate devices when a primary ID is missing.
    if let Ok(host) = env::var("HOSTNAME").or_else(|_| env::var("COMPUTERNAME")) {
        components.push(host);
    }
    if let Ok(user) = env::var("USER").or_else(|_| env::var("USERNAME")) {
        components.push(user);
    }

    // Always include the OS so dual-boot setups derive distinct values.
    components.push(env::consts::OS.to_string());

    let mut hasher = Sha256::new();
    for part in components {
        hasher.update(part.as_bytes());
    }

    let digest = hasher.finalize();
    Ok(hex_encode(digest))
}

#[cfg(target_os = "linux")]
fn platform_unique_identifier() -> Option<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(contents) = fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn platform_unique_identifier() -> Option<String> {
    // ioreg typically exposes the hardware UUID reliably.
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(rest) = line.split("IOPlatformUUID").nth(1) {
                if let Some(uuid_part) = rest.split('=').nth(1) {
                    let candidate = uuid_part.trim().trim_matches('"').to_string();
                    if !candidate.is_empty() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    // Fallback to system_profiler for environments where ioreg output changed.
    let alt_output = Command::new("system_profiler")
        .args(["SPHardwareDataType"])
        .output()
        .ok()?;
    if alt_output.status.success() {
        let stdout = String::from_utf8_lossy(&alt_output.stdout);
        for line in stdout.lines() {
            if let Some(rest) = line.split(':').nth(1) {
                if line.contains("Hardware UUID") {
                    let candidate = rest.trim().to_string();
                    if !candidate.is_empty() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn platform_unique_identifier() -> Option<String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cryptography = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography").ok()?;
    cryptography.get_value("MachineGuid").ok()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn platform_unique_identifier() -> Option<String> {
    None
}

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
    pub fn new(folder_path: &str, store_name: &str, password: &str) -> Result<Self> {
        let path = Path::new(folder_path).join(format!("{}.cos", store_name));
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
    use std::{fs, path::Path};

    fn get_temp_path() -> (String, String) {
        let mut rng = rand::rng();
        let id: u32 = rng.random();
        let path = std::env::temp_dir();
        let file_name = format!("cube_store_test_{}", id);
        (path.to_string_lossy().into_owned(), file_name)
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct User {
        id: u32,
        name: String,
        active: bool,
    }

    #[test]
    fn machine_password_is_stable_and_non_empty() -> Result<()> {
        let first = machine_password()?;
        let second = machine_password()?;

        assert!(!first.is_empty());
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn test_basic_operations() -> Result<()> {
        let (folder, file) = get_temp_path();
        let password = "secure_password";
        let full_path = Path::new(&folder).join(format!("{}.cos", file));

        // Clean up previous run if exists (unlikely with random name)
        if full_path.exists() {
            fs::remove_file(&full_path)?;
        }

        {
            let mut store = ObjectStore::new(&folder, &file, password)?;

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

        fs::remove_file(full_path).ok();
        Ok(())
    }

    #[test]
    fn test_persistence() -> Result<()> {
        let (folder, file) = get_temp_path();
        let full_path = Path::new(&folder).join(format!("{}.cos", file));
        let password = "persistent_pass";

        let user = User {
            id: 1,
            name: "Alice".into(),
            active: true,
        };

        {
            let mut store = ObjectStore::new(&folder, &file, password)?;
            store.insert("user", &user)?;
        } // store dropped, flushed

        {
            let store = ObjectStore::new(&folder, &file, password)?;
            let retrieved: Option<User> = store.get("user")?;
            assert_eq!(retrieved, Some(user));
        }

        fs::remove_file(full_path).ok();
        Ok(())
    }

    #[test]
    fn test_wrong_password() -> Result<()> {
        let (folder, file) = get_temp_path();
        let full_path = Path::new(&folder).join(format!("{}.cos", file));
        let password = "correct_pass";

        {
            let mut store = ObjectStore::new(&folder, &file, password)?;
            store.insert("secret", &"data")?;
        }

        // Try opening with wrong password
        let result = ObjectStore::new(&folder, &file, "wrong_pass");
        assert!(result.is_err());

        fs::remove_file(full_path).ok();
        Ok(())
    }
}
