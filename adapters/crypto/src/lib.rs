use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use argon2::Argon2;
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::RwLock;

use lms_core::{Vault, VaultProvider};

// ==========================================
// ENVELOPE FORMAT
// ==========================================

/// The physical format of the encrypted payload.
/// Salt and nonce are public requirements for the math to work;
/// only the ciphertext is secret.
#[derive(Serialize, Deserialize)]
struct EncryptedVault {
    salt: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ==========================================
// CRYPTO PRIMITIVES (shared)
// ==========================================

/// Derive a 32-byte key from a password and salt via Argon2.
fn derive_key(password: &str, salt_bytes: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    Ok(key)
}

/// Encrypt arbitrary bytes with a password. Generates a fresh random salt
/// and nonce on every call. Returns a serialized envelope.
fn seal(plaintext: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let salt = SaltString::generate(&mut OsRng);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, salt.as_str().as_bytes())?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| "Encryption failed".to_string())?;

    let env = EncryptedVault {
        salt: salt.to_string(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };
    serde_json::to_vec(&env).map_err(|e| e.to_string())
}

/// Decrypt a serialized envelope produced by `seal`.
fn open(envelope_bytes: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let env: EncryptedVault = serde_json::from_slice(envelope_bytes)
        .map_err(|e| format!("Corrupt vault format: {}", e))?;

    let salt = SaltString::from_b64(&env.salt)
        .map_err(|_| "Invalid salt format".to_string())?;
    let key = derive_key(password, salt.as_str().as_bytes())?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&env.nonce);

    cipher
        .decrypt(nonce, env.ciphertext.as_ref())
        .map_err(|_| "Wrong password or corrupted data".to_string())
}

// ==========================================
// PUBLIC HELPERS (for the WASM sensor, etc.)
// ==========================================

/// Encrypt a JSON string with a password. Output is a self-contained envelope
/// (salt + nonce + ciphertext) safe to store on disk or transmit.
pub fn encrypt_vault(json_data: &str, password: &str) -> Result<Vec<u8>, String> {
    seal(json_data.as_bytes(), password)
}

/// Decrypt an envelope produced by `encrypt_vault` and return the JSON string.
pub fn decrypt_vault(encrypted_data: &[u8], password: &str) -> Result<String, String> {
    let plaintext = open(encrypted_data, password)?;
    String::from_utf8(plaintext).map_err(|_| "Invalid UTF-8 after decryption".to_string())
}

// ==========================================
// LOCAL FILE-SYSTEM PROVIDER
// ==========================================

/// The Local File-System Cryptography Plugin.
pub struct LocalCryptoProvider {
    /// Where the encrypted file lives on disk.
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

impl VaultProvider for LocalCryptoProvider {
    fn authenticate_and_load(&self, credentials: &str) -> Result<Vault, String> {
        // SCENARIO A: Brand new user — file doesn't exist yet.
        if !self.path.exists() {
            *self.session_password.write().unwrap() = Some(credentials.to_string());
            return Ok(Vault::new());
        }

        // SCENARIO B: Returning user — read and decrypt.
        let bytes = std::fs::read(&self.path)
            .map_err(|e| format!("Could not read vault file: {}", e))?;

        let plaintext = open(&bytes, credentials)?;
        let json = String::from_utf8(plaintext)
            .map_err(|_| "Invalid UTF-8 after decryption".to_string())?;

        // Cache password for subsequent saves.
        *self.session_password.write().unwrap() = Some(credentials.to_string());

        Vault::from_json(&json).map_err(|e| e.to_string())
    }

    fn save_state(&self, vault: &Vault) -> Result<(), String> {
        let pwd_guard = self.session_password.read().unwrap();
        let password = pwd_guard.as_ref()
            .ok_or("No active session. Please authenticate first.")?;

        let json = vault.to_json().map_err(|e| e.to_string())?;
        let envelope = seal(json.as_bytes(), password)?;

        std::fs::write(&self.path, envelope)
            .map_err(|e| format!("Could not write vault to disk: {}", e))
    }
}