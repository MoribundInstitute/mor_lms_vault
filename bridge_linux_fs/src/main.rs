use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, Read, Write};
use std::str::FromStr;

use age::x25519::Recipient;
use lms_crypto::{KeyringKeySource, Vault, VaultPaths};

const MAX_INCOMING: usize = 64 * 1024 * 1024;
const MAX_OUTGOING: usize = 1024 * 1024;

// Single-user, local-first vault. The OS login session (which unlocks the
// keyring) is the only authentication there is — there is no remote identity
// provider. `user_id` is just the keyring slot label, so a constant is fine.
// Swap to std::env::var("USER") if you prefer it tied to the OS account name.
const LOCAL_USER: &str = "moribund_local";

#[derive(Deserialize)]
struct IncomingMessage {
    command: String,
    payload: Option<Value>,
}

// All we persist on disk is the device's PUBLIC recipient (so `save` knows who
// to encrypt to). The matching private key never leaves the OS keyring.
#[derive(Serialize, Deserialize)]
struct AppState {
    device_pubkey: String,
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let mut len_bytes = [0u8; 4];
        if reader.read_exact(&mut len_bytes).is_err() {
            break;
        }
        let len = u32::from_ne_bytes(len_bytes) as usize;

        if len > MAX_INCOMING {
            break;
        }

        let mut buffer = vec![0u8; len];
        if reader.read_exact(&mut buffer).is_err() {
            break;
        }

        if let Ok(msg) = serde_json::from_slice::<IncomingMessage>(&buffer) {
            let response = match msg.command.as_str() {
                "fetch_feed" => handle_fetch(),
                "save_vault" => handle_save(msg.payload),
                "unlock" => handle_unlock(),
                _ => serde_json::json!({"error": "Unknown command"}),
            };

            if send_message(&mut writer, &response).is_err() {
                break;
            }
        }
    }
}

fn send_message<W: Write>(writer: &mut W, msg: &Value) -> io::Result<()> {
    let msg_str = msg.to_string();
    let bytes = msg_str.as_bytes();

    if bytes.len() > MAX_OUTGOING {
        let err = serde_json::json!({"error": "response_too_large"}).to_string();
        let err_bytes = err.as_bytes();
        writer.write_all(&(err_bytes.len() as u32).to_ne_bytes())?;
        writer.write_all(err_bytes)?;
        return writer.flush();
    }

    writer.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

// --- Paths ---

fn get_state_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    fs::create_dir_all(format!("{}/mor_lms_vault", home)).ok();
    format!("{}/mor_lms_vault/state.json", home)
}

fn get_vault_paths() -> VaultPaths {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    fs::create_dir_all(format!("{}/mor_lms_vault", home)).ok();
    VaultPaths::from_base(format!("{}/mor_lms_vault/my_brain", home))
}

fn load_state() -> Option<AppState> {
    let data = fs::read_to_string(get_state_path()).ok()?;
    serde_json::from_str(&data).ok()
}

// --- Unlock / first-run provisioning ---
//
// There is no login. On first run we generate an x25519 device keypair; the
// private half is sealed into the OS keyring (unlocked by your desktop session)
// and we cache the public recipient on disk. Every run after that is a no-op
// that just confirms the vault is ready.
//
// This MUST stay idempotent: provision_device() mints a fresh key and overwrites
// the keyring slot, which would orphan an existing vault — so we only provision
// when no state has been written yet.
fn handle_unlock() -> Value {
    if let Some(state) = load_state() {
        return serde_json::json!({"status": "unlocked", "pubkey": state.device_pubkey});
    }

    let source = KeyringKeySource::new(LOCAL_USER, vec![]);
    let pubkey = match source.provision_device() {
        Ok(pk) => pk,
        Err(e) => return serde_json::json!({"error": format!("Keyring failed: {}", e)}),
    };

    let state = AppState {
        device_pubkey: pubkey.to_string(),
    };
    if let Err(e) = fs::write(get_state_path(), serde_json::to_string(&state).unwrap()) {
        return serde_json::json!({"error": format!("Failed to persist state: {}", e)});
    }

    serde_json::json!({"status": "provisioned", "pubkey": pubkey.to_string()})
}

// --- Read the vault ---
fn handle_fetch() -> Value {
    let paths = get_vault_paths();
    if !paths.enc.exists() {
        return serde_json::json!([]); // Nothing stored yet.
    }

    // Pull the private key from the (OS-login-unlocked) keyring and stream-decrypt.
    let source = KeyringKeySource::new(LOCAL_USER, vec![]);
    let mut pt = Vec::new();
    match Vault::open_to(&paths, &source, &mut pt) {
        Ok(_) => serde_json::from_slice(&pt).unwrap_or_else(|_| serde_json::json!([])),
        Err(e) => {
            eprintln!("Vault decryption failed: {}", e);
            serde_json::json!([])
        }
    }
}

// --- Write the vault ---
fn handle_save(payload: Option<Value>) -> Value {
    let vault_data = match payload {
        Some(v) => v,
        None => return serde_json::json!({"error": "No payload provided"}),
    };

    let state = match load_state() {
        Some(s) => s,
        None => return serde_json::json!({"error": "Vault not initialized; send `unlock` first"}),
    };

    let pubkey = match Recipient::from_str(&state.device_pubkey) {
        Ok(pk) => pk,
        Err(_) => return serde_json::json!({"error": "Invalid device public key"}),
    };

    let paths = get_vault_paths();
    let plaintext = vault_data.to_string();

    // Encrypt the vault, wrapping the DEK to this device's recipient.
    match Vault::init(&paths, &[pubkey], None, std::io::Cursor::new(plaintext)) {
        Ok(_) => serde_json::json!({"status": "vault_secured"}),
        Err(e) => serde_json::json!({"error": format!("Encryption failed: {}", e)}),
    }
}