use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use argon2::Argon2;
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::RwLock;

// Import the pure traits and structs from our core engine
use lms_core::{Vault, VaultProvider};

/// The physical format of the data saved to the hard drive.
/// The salt and nonce are public requirements for the math to work; 
/// only the ciphertext is secret.
#[derive(Serialize, Deserialize)]
struct EncryptedVault {
    salt: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// The Local File-System Cryptography Plugin.
pub struct LocalCryptoProvider {
    /// Where the encrypted file lives on the hard drive
    path: PathBuf,
    /// Caches the password in memory during an active session so `save_state` works.
    session_password: RwLock<Option<String>>,
}

impl LocalCryptoProvider {
    /// Initialize the provider with a target file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            session_password: RwLock::new(None),
        }
    }
}

/// Helper: Turns a human password into a raw 32-byte cryptographic key.
fn derive_key(password: &str, salt: &SaltString) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    Ok(key)
}

// ==========================================
// THE CONTRACT IMPLEMENTATION
// ==========================================

impl VaultProvider for LocalCryptoProvider {
    fn authenticate_and_load(&self, credentials: &str) -> Result<Vault, String> {
        // SCENARIO A: Brand new user (File doesn't exist yet)
        if !self.path.exists() {
            // Cache their new password for when they eventually save, and return an empty vault
            *self.session_password.write().unwrap() = Some(credentials.to_string());
            return Ok(Vault::new());
        }

        // SCENARIO B: Returning user (Read and decrypt the file)
        let bytes = std::fs::read(&self.path)
            .map_err(|e| format!("Could not read vault file: {}", e))?;

        let enc: EncryptedVault = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Corrupt vault file format: {}", e))?;

        let salt = SaltString::from_b64(&enc.salt)
            .map_err(|_| "Invalid salt format".to_string())?;

        // 1. Derive the key
        let key = derive_key(credentials, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(&enc.nonce);

        // 2. Unlock the data
        let plaintext = cipher.decrypt(nonce, enc.ciphertext.as_ref())
            .map_err(|_| "Wrong password or corrupted data".to_string())?;

        let json = String::from_utf8(plaintext)
            .map_err(|_| "Invalid UTF-8 after decryption".to_string())?;

        // 3. Success! Cache the password in memory for saving later
        *self.session_password.write().unwrap() = Some(credentials.to_string());

        // 4. Return the fully hydrated Vault to the GUI
        Vault::from_json(&json).map_err(|e| e.to_string())
    }

    fn save_state(&self, vault: &Vault) -> Result<(), String> {
        // Ensure the user actually logged in before trying to save
        let pwd_guard = self.session_password.read().unwrap();
        let password = pwd_guard.as_ref()
            .ok_or("No active session. Please authenticate first.")?;

        // 1. Convert the memory state into a JSON string
        let json = vault.to_json().map_err(|e| e.to_string())?;

        // 2. Generate a fresh, random Salt and Nonce to ensure maximum security
        let salt = SaltString::generate(&mut OsRng);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // 3. Lock it down
        let key = derive_key(password, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), json.as_bytes())
            .map_err(|_| "Encryption failed".to_string())?;

        let enc = EncryptedVault {
            salt: salt.to_string(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };

        // 4. Save to disk
        let out = serde_json::to_vec(&enc).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, out)
            .map_err(|e| format!("Could not write vault to disk: {}", e))
    }
}
