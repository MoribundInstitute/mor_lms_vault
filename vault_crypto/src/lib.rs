//! adapters/crypto — explicit DEK + age-wrapped keyslots + STREAM AEAD bulk.
//!
//! TRUST MODEL
//!   * The OS keyring (gated by the OS login session) protects this device's
//!     age identity. That gate is the real cryptographic boundary.
//!   * `LocalSession.user_id` selects the keyring slot and authorizes the
//!     attempt; it is NEVER key material.
//!   * A stable 32-byte DEK encrypts the bulk vault. `age` is used strictly to
//!     wrap that DEK per keyslot. Device churn re-wraps a 60-byte manifest;
//!     the bulk file is left alone.
//!
//! FILE LAYOUT (sibling files, common base name)
//!     my_brain.enc              chunked ChaCha20-Poly1305 STREAM ciphertext
//!     my_brain.keys.devices     age file: DEK manifest -> x25519 device recipients
//!     my_brain.keys.passphrase  age file: DEK manifest -> scrypt passphrase recipient
//!
//! WHY TWO .keys.* FILES (NOT ONE)
//!   The age format spec forbids mixing an scrypt recipient with any other
//!   recipient type in the same file (it would break the implicit "sender knew
//!   the passphrase" property of passphrase decryption). So device-pubkey and
//!   passphrase keyslots are necessarily separate age files wrapping the same
//!   60-byte DEK manifest. Either one alone unlocks the vault.
//!
//! Cargo.toml (workspace member adapters/crypto)
//!     age              = "0.11.3"                             # pin past the 0.11.0 plugin CVE
//!     keyring          = { version = "4", features = [
//!                          "apple-native", "windows-native",
//!                          "sync-secret-service", "linux-native"] }
//!     chacha20poly1305 = { version = "0.10", features = ["stream"] }   # matches age's own dep
//!     rand             = "0.8"
//!     zeroize          = { version = "1", features = ["derive"] }
//!     anyhow           = "1"

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use keyring::Entry;
use rand::RngCore;
use zeroize::Zeroizing;

// ── format constants ────────────────────────────────────────────────────────
const KEYRING_SERVICE: &str = "mor_lms_vault";
const ENC_MAGIC:  [u8; 8] = *b"MORBRN01";
const KEY_MAGIC:  [u8; 4] = *b"MKEY";
const ENC_HEADER_LEN: usize = 44;
const MANIFEST_LEN:   usize = 60;
const CHUNK_SIZE: usize = 65_536;
const TAG_LEN:    usize = 16;                       // Poly1305 tag
const CT_CHUNK_LEN: usize = CHUNK_SIZE + TAG_LEN;
const NONCE_PREFIX_LEN: usize = 7;                  // STREAM-BE32

// ── KeySource: abstracts where age identities/recipients come from ──────────

pub trait KeySource {
    fn recipients(&self) -> anyhow::Result<Vec<Box<dyn age::Recipient>>>;
    fn identities(&self) -> anyhow::Result<Vec<Box<dyn age::Identity>>>;
}

/// Default desktop source: this device's age identity lives in the OS keyring,
/// namespaced by the verified `user_id` so identities coexist on one machine.
/// `peer_recipients` is the full set of enrolled-device public keys — they are
/// not secret and normally come from the vault's recipient roster.
pub struct KeyringKeySource {
    user_id: String,
    peer_recipients: Vec<x25519::Recipient>,
}

impl KeyringKeySource {
    pub fn new(user_id: impl Into<String>, peer_recipients: Vec<x25519::Recipient>) -> Self {
        Self { user_id: user_id.into(), peer_recipients }
    }

    fn entry(&self) -> anyhow::Result<Entry> {
        Ok(Entry::new(KEYRING_SERVICE, &self.user_id)?)
    }

    /// One-time per device. Returns the PUBLIC recipient to register with the vault.
    pub fn provision_device(&self) -> anyhow::Result<x25519::Recipient> {
        let id = x25519::Identity::generate();
        let pubkey = id.to_public();
        // `to_string()` is age 0.11.3's inherent method returning SecretString —
        // it does NOT implement Display, so this won't accidentally leak via
        // formatting. We hand the inner &str to the keyring only at the call
        // site; the SecretString zeroises on drop at the end of this scope.
        let secret = id.to_string();
        self.entry()?.set_password(secret.expose_secret())?;
        Ok(pubkey)
    }
}

impl KeySource for KeyringKeySource {
    fn recipients(&self) -> anyhow::Result<Vec<Box<dyn age::Recipient>>> {
        Ok(self.peer_recipients.iter().cloned()
            .map(|r| Box::new(r) as Box<dyn age::Recipient>)
            .collect())
    }
    fn identities(&self) -> anyhow::Result<Vec<Box<dyn age::Identity>>> {
        // OS keyring is unlocked by OS login; this read just retrieves the stored secret.
        let secret = self.entry()?.get_password()?;
        let id: x25519::Identity = secret.parse()
            .map_err(|e| anyhow::anyhow!("stored identity is not a valid age key: {e}"))?;
        Ok(vec![Box::new(id)])
    }
}

/// Headless / keyring-unavailable fallback: a passphrase keyslot (age scrypt).
/// Lives in its own .keys.passphrase file (format requires this).
pub struct PassphraseKeySource {
    passphrase: SecretString,
}

impl PassphraseKeySource {
    pub fn new(passphrase: SecretString) -> Self { Self { passphrase } }
}

impl KeySource for PassphraseKeySource {
    fn recipients(&self) -> anyhow::Result<Vec<Box<dyn age::Recipient>>> {
        Ok(vec![Box::new(age::scrypt::Recipient::new(self.passphrase.clone()))])
    }
    fn identities(&self) -> anyhow::Result<Vec<Box<dyn age::Identity>>> {
        Ok(vec![Box::new(age::scrypt::Identity::new(self.passphrase.clone()))])
    }
}

// ── DEK manifest (plaintext of .keys.* files) ───────────────────────────────

#[derive(Clone)]
pub struct DekManifest {
    pub vault_uuid: [u8; 16],
    pub dek_version: u32,
    pub dek: Zeroizing<[u8; 32]>,
}

impl DekManifest {
    fn to_bytes(&self) -> Zeroizing<[u8; MANIFEST_LEN]> {
        let mut buf = Zeroizing::new([0u8; MANIFEST_LEN]);
        buf[0..4].copy_from_slice(&KEY_MAGIC);
        buf[4..20].copy_from_slice(&self.vault_uuid);
        buf[20..24].copy_from_slice(&self.dek_version.to_le_bytes());
        buf[24..56].copy_from_slice(self.dek.as_ref());
        // 56..60 reserved
        buf
    }

    fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        if b.len() != MANIFEST_LEN { anyhow::bail!("manifest length mismatch"); }
        if b[0..4] != KEY_MAGIC    { anyhow::bail!("manifest magic mismatch"); }
        let mut uuid = [0u8; 16]; uuid.copy_from_slice(&b[4..20]);
        let ver = u32::from_le_bytes(b[20..24].try_into().unwrap());
        let mut dek = [0u8; 32]; dek.copy_from_slice(&b[24..56]);
        Ok(Self { vault_uuid: uuid, dek_version: ver, dek: Zeroizing::new(dek) })
    }
}

// ── .enc header (44 bytes, becomes AAD for every chunk) ─────────────────────

#[derive(Clone, Copy)]
pub struct EncHeader {
    pub vault_uuid: [u8; 16],
    pub dek_version: u32,
    pub chunk_size: u32,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl EncHeader {
    fn to_bytes(&self) -> [u8; ENC_HEADER_LEN] {
        let mut buf = [0u8; ENC_HEADER_LEN];
        buf[0..8].copy_from_slice(&ENC_MAGIC);
        buf[8..24].copy_from_slice(&self.vault_uuid);
        buf[24..28].copy_from_slice(&self.dek_version.to_le_bytes());
        buf[28..32].copy_from_slice(&self.chunk_size.to_le_bytes());
        buf[32..39].copy_from_slice(&self.nonce_prefix);
        // 39..44 reserved
        buf
    }

    fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        if b.len() != ENC_HEADER_LEN { anyhow::bail!("enc header length mismatch"); }
        if b[0..8] != ENC_MAGIC      { anyhow::bail!("enc magic mismatch / wrong file"); }
        let mut uuid = [0u8; 16]; uuid.copy_from_slice(&b[8..24]);
        let ver   = u32::from_le_bytes(b[24..28].try_into().unwrap());
        let chunk = u32::from_le_bytes(b[28..32].try_into().unwrap());
        let mut np = [0u8; NONCE_PREFIX_LEN]; np.copy_from_slice(&b[32..39]);
        Ok(Self { vault_uuid: uuid, dek_version: ver, chunk_size: chunk, nonce_prefix: np })
    }
}

// ── conventional path layout for the three sibling files ────────────────────

pub struct VaultPaths {
    pub enc: PathBuf,
    pub keys_devices: PathBuf,
    pub keys_passphrase: PathBuf,
}

impl VaultPaths {
    /// `base` = "/data/my_brain" yields the three sibling files described above.
    pub fn from_base(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        let stem = base.file_name().unwrap_or_default().to_os_string();
        let parent = base.parent().unwrap_or(Path::new("."));
        let join = |suffix: &str| {
            let mut name = stem.clone();
            name.push(suffix);
            parent.join(name)
        };
        Self {
            enc:             join(".enc"),
            keys_devices:    join(".keys.devices"),
            keys_passphrase: join(".keys.passphrase"),
        }
    }
}

// ── internal helpers: wrap/unwrap the manifest via age ──────────────────────

fn wrap_manifest_to(
    manifest_bytes: &[u8],
    recipients: &[Box<dyn age::Recipient>],
    out: impl Write,
) -> anyhow::Result<()> {
    let encryptor = age::Encryptor::with_recipients(
        recipients.iter().map(|r| r.as_ref())
    )?;
    let mut writer = encryptor.wrap_output(out)?;
    writer.write_all(manifest_bytes)?;
    writer.finish()?;                       // REQUIRED — else truncated, undecryptable
    Ok(())
}

fn unwrap_manifest_from(
    reader: impl Read,
    identities: &[Box<dyn age::Identity>],
) -> anyhow::Result<DekManifest> {
    let decryptor = age::Decryptor::new(reader)?;
    let mut stream = decryptor.decrypt(identities.iter().map(|i| i.as_ref()))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(MANIFEST_LEN));
    stream.read_to_end(&mut buf)?;
    DekManifest::from_bytes(&buf)
}

// ── bulk file: ChaCha20-Poly1305 STREAM-BE32, header bound as AAD ───────────

fn seal_bulk(
    dek: &[u8; 32],
    header: &EncHeader,
    mut plaintext: impl Read,
    mut out: impl Write,
) -> anyhow::Result<()> {
    let header_bytes = header.to_bytes();
    out.write_all(&header_bytes)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(dek));
    let nonce_prefix = GenericArray::from_slice(&header.nonce_prefix);
    let mut enc = EncryptorBE32::from_aead(cipher, nonce_prefix);

    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = read_full(&mut plaintext, &mut buf)?;
        if n < CHUNK_SIZE {
            // EOF reached — this is the last chunk (may be empty, that's fine).
            let ct = enc.encrypt_last(Payload { msg: &buf[..n], aad: &header_bytes })
                .map_err(|e| anyhow::anyhow!("encrypt_last: {e}"))?;
            out.write_all(&ct)?;
            break;
        }
        let ct = enc.encrypt_next(Payload { msg: &buf, aad: &header_bytes })
            .map_err(|e| anyhow::anyhow!("encrypt_next: {e}"))?;
        out.write_all(&ct)?;
    }
    out.flush()?;
    Ok(())
}

fn open_bulk_to(
    dek: &[u8; 32],
    expected_uuid: &[u8; 16],
    expected_version: u32,
    mut ciphertext: impl Read,
    mut out: impl Write,
) -> anyhow::Result<()> {
    let mut header_bytes = [0u8; ENC_HEADER_LEN];
    ciphertext.read_exact(&mut header_bytes)?;
    let header = EncHeader::from_bytes(&header_bytes)?;
    if &header.vault_uuid != expected_uuid {
        anyhow::bail!(".keys / .enc vault_uuid mismatch");
    }
    if header.dek_version != expected_version {
        anyhow::bail!(".keys / .enc dek_version mismatch (stale keyfile?)");
    }
    if header.chunk_size as usize != CHUNK_SIZE {
        anyhow::bail!("unsupported chunk_size {}", header.chunk_size);
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(dek));
    let nonce_prefix = GenericArray::from_slice(&header.nonce_prefix);
    let mut dec = DecryptorBE32::from_aead(cipher, nonce_prefix);

    let mut buf = vec![0u8; CT_CHUNK_LEN];
    loop {
        let n = read_full(&mut ciphertext, &mut buf)?;
        if n < CT_CHUNK_LEN {
            if n < TAG_LEN { anyhow::bail!("truncated last chunk"); }
            let pt = dec.decrypt_last(Payload { msg: &buf[..n], aad: &header_bytes })
                .map_err(|e| anyhow::anyhow!("decrypt_last: {e} (tamper or wrong key)"))?;
            out.write_all(&pt)?;
            break;
        }
        let pt = dec.decrypt_next(Payload { msg: &buf, aad: &header_bytes })
            .map_err(|e| anyhow::anyhow!("decrypt_next: {e} (tamper or wrong key)"))?;
        out.write_all(&pt)?;
    }
    out.flush()?;
    Ok(())
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

// ── Vault orchestrator ──────────────────────────────────────────────────────

pub struct Vault;

impl Vault {
    /// First-time creation. Generates DEK + vault_uuid + nonce_prefix.
    /// Both .keys.* files are written. Pass `passphrase = None` to skip the
    /// passphrase keyslot (only do this if you accept losing all devices = data loss).
    pub fn init(
        paths: &VaultPaths,
        devices: &[x25519::Recipient],
        passphrase: Option<SecretString>,
        plaintext: impl Read,
    ) -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let mut dek = [0u8; 32]; rng.fill_bytes(&mut dek);
        let mut vault_uuid = [0u8; 16]; rng.fill_bytes(&mut vault_uuid);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN]; rng.fill_bytes(&mut nonce_prefix);

        let manifest = DekManifest {
            vault_uuid,
            dek_version: 1,
            dek: Zeroizing::new(dek),
        };
        let mbytes = manifest.to_bytes();

        // .keys.devices
        let device_recipients: Vec<Box<dyn age::Recipient>> = devices.iter().cloned()
            .map(|r| Box::new(r) as Box<dyn age::Recipient>).collect();
        let tmp = with_suffix(&paths.keys_devices, ".tmp");
        wrap_manifest_to(mbytes.as_ref(), &device_recipients, std::fs::File::create(&tmp)?)?;
        std::fs::rename(&tmp, &paths.keys_devices)?;

        // .keys.passphrase
        if let Some(pw) = passphrase {
            let pw_recipients: Vec<Box<dyn age::Recipient>> = vec![
                Box::new(age::scrypt::Recipient::new(pw))
            ];
            let tmp = with_suffix(&paths.keys_passphrase, ".tmp");
            wrap_manifest_to(mbytes.as_ref(), &pw_recipients, std::fs::File::create(&tmp)?)?;
            std::fs::rename(&tmp, &paths.keys_passphrase)?;
        }

        // .enc — write last so a half-baked vault never leaves a stranded keyfile.
        let header = EncHeader { vault_uuid, dek_version: 1, chunk_size: CHUNK_SIZE as u32, nonce_prefix };
        let tmp = with_suffix(&paths.enc, ".tmp");
        seal_bulk(&*manifest.dek, &header, plaintext, std::fs::File::create(&tmp)?)?;
        std::fs::rename(&tmp, &paths.enc)?;
        Ok(())
    }

    /// Unlock and stream plaintext to `out`. `src` chooses the keyslot.
    /// Try `KeyringKeySource` first; on failure, fall back to `PassphraseKeySource`.
    pub fn open_to(
        paths: &VaultPaths,
        src: &dyn KeySource,
        out: impl Write,
    ) -> anyhow::Result<()> {
        // Pick the right .keys.* file based on source type via duck-typing:
        // try devices first, then passphrase, by attempting each in order if
        // a single source could represent either. Simpler: caller passes the
        // matching source; we open the keyfile whose recipient class matches.
        // Heuristic: try .keys.devices if it exists and source yields a non-scrypt
        // identity; else .keys.passphrase. Cleanest: caller passes which.
        let identities = src.identities()?;
        let manifest = open_first_matching_keyfile(paths, &identities)?;

        let enc = std::fs::File::open(&paths.enc)?;
        open_bulk_to(&*manifest.dek, &manifest.vault_uuid, manifest.dek_version, enc, out)
    }

    /// Enroll a new device pubkey. Only `.keys.devices` is rewritten; `.enc` is untouched.
    pub fn enroll_device(
        paths: &VaultPaths,
        existing: &dyn KeySource,                    // already-trusted source on this machine
        current_devices: &[x25519::Recipient],
        new_device: x25519::Recipient,
    ) -> anyhow::Result<()> {
        let identities = existing.identities()?;
        let f = std::fs::File::open(&paths.keys_devices)?;
        let manifest = unwrap_manifest_from(f, &identities)?;
        let mbytes = manifest.to_bytes();

        let mut all = current_devices.to_vec();
        all.push(new_device);
        let recipients: Vec<Box<dyn age::Recipient>> = all.into_iter()
            .map(|r| Box::new(r) as Box<dyn age::Recipient>).collect();

        let tmp = with_suffix(&paths.keys_devices, ".tmp");
        wrap_manifest_to(mbytes.as_ref(), &recipients, std::fs::File::create(&tmp)?)?;
        std::fs::rename(&tmp, &paths.keys_devices)?;
        Ok(())
    }

    /// Generate a new DEK, bump version, re-stream `.enc`, rewrite both `.keys.*`.
    /// This is the only operation that touches the bulk file.
    pub fn rotate_dek(
        paths: &VaultPaths,
        existing: &dyn KeySource,
        devices: &[x25519::Recipient],
        passphrase: Option<SecretString>,
    ) -> anyhow::Result<()> {
        // Decrypt with the old DEK into a temp file, then re-seal.
        let identities = existing.identities()?;
        let old_manifest = open_first_matching_keyfile(paths, &identities)?;

        let pt_tmp = with_suffix(&paths.enc, ".rotate.pt.tmp");
        {
            let enc = std::fs::File::open(&paths.enc)?;
            let out = std::fs::File::create(&pt_tmp)?;
            open_bulk_to(
                &*old_manifest.dek,
                &old_manifest.vault_uuid,
                old_manifest.dek_version,
                enc,
                out,
            )?;
        }

        let new_paths = VaultPaths {
            enc: paths.enc.clone(),
            keys_devices: paths.keys_devices.clone(),
            keys_passphrase: paths.keys_passphrase.clone(),
        };
        // Bump version, preserve vault_uuid (it's the vault's identity).
        let mut rng = rand::thread_rng();
        let mut new_dek = [0u8; 32]; rng.fill_bytes(&mut new_dek);
        let mut new_np = [0u8; NONCE_PREFIX_LEN]; rng.fill_bytes(&mut new_np);
        let new_manifest = DekManifest {
            vault_uuid: old_manifest.vault_uuid,
            dek_version: old_manifest.dek_version.checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("dek_version overflow"))?,
            dek: Zeroizing::new(new_dek),
        };
        let mbytes = new_manifest.to_bytes();

        // Rewrite both .keys.* under the new DEK
        let device_rs: Vec<Box<dyn age::Recipient>> = devices.iter().cloned()
            .map(|r| Box::new(r) as Box<dyn age::Recipient>).collect();
        let tmp_d = with_suffix(&new_paths.keys_devices, ".tmp");
        wrap_manifest_to(mbytes.as_ref(), &device_rs, std::fs::File::create(&tmp_d)?)?;

        let tmp_p = if let Some(pw) = passphrase {
            let pw_rs: Vec<Box<dyn age::Recipient>> = vec![Box::new(age::scrypt::Recipient::new(pw))];
            let p = with_suffix(&new_paths.keys_passphrase, ".tmp");
            wrap_manifest_to(mbytes.as_ref(), &pw_rs, std::fs::File::create(&p)?)?;
            Some(p)
        } else { None };

        // Re-seal .enc
        let new_header = EncHeader {
            vault_uuid: new_manifest.vault_uuid,
            dek_version: new_manifest.dek_version,
            chunk_size: CHUNK_SIZE as u32,
            nonce_prefix: new_np,
        };
        let enc_tmp = with_suffix(&new_paths.enc, ".tmp");
        {
            let pt = std::fs::File::open(&pt_tmp)?;
            let out = std::fs::File::create(&enc_tmp)?;
            seal_bulk(&*new_manifest.dek, &new_header, pt, out)?;
        }

        // Atomic flip: .enc first, then keyfiles, so a crash never strands a key
        // that can't decrypt anything.
        std::fs::rename(&enc_tmp, &new_paths.enc)?;
        std::fs::rename(&tmp_d, &new_paths.keys_devices)?;
        if let Some(p) = tmp_p { std::fs::rename(&p, &new_paths.keys_passphrase)?; }
        std::fs::remove_file(&pt_tmp).ok();          // best-effort; pt_tmp is sensitive
        Ok(())
    }
}

fn open_first_matching_keyfile(
    paths: &VaultPaths,
    identities: &[Box<dyn age::Identity>],
) -> anyhow::Result<DekManifest> {
    // Try .keys.devices then .keys.passphrase. The age decryptor itself will
    // reject mismatched identities, so trying both in order is safe.
    if paths.keys_devices.exists() {
        if let Ok(m) = unwrap_manifest_from(std::fs::File::open(&paths.keys_devices)?, identities) {
            return Ok(m);
        }
    }
    if paths.keys_passphrase.exists() {
        return unwrap_manifest_from(std::fs::File::open(&paths.keys_passphrase)?, identities);
    }
    anyhow::bail!("no usable .keys.* file");
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}