use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::{Entry as KeyringEntry, Error as KeyringError};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use zeroize::{Zeroize, Zeroizing};

const VAULT_FILE_NAME: &str = "vault.encrypted.json";
const KEYRING_SERVICE: &str = "com.elias.passwordmanager";
const KEYRING_USER: &str = "master_password_hash";
const MIN_MASTER_PASSWORD_LENGTH: usize = 12;
const AES_KEY_LENGTH: usize = 32;
const AES_NONCE_LENGTH: usize = 12;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfConfig {
    salt_b64: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedVaultFile {
    version: u8,
    kdf: KdfConfig,
    nonce_b64: String,
    ciphertext_b64: String,
    updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(rename_all = "camelCase")]
struct PasswordEntry {
    id: String,
    service: String,
    username: String,
    password: String,
    notes: String,
    url: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(rename_all = "camelCase")]
struct DecryptedVault {
    entries: Vec<PasswordEntry>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryInput {
    service: String,
    username: String,
    password: String,
    notes: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEntryInput {
    id: String,
    service: String,
    username: String,
    password: String,
    notes: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordGenerationRequest {
    length: u8,
    include_numbers: bool,
    include_symbols: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    initialized: bool,
    unlocked: bool,
}

#[derive(Debug)]
struct VaultRuntime {
    vault_path: PathBuf,
    decrypted_vault: Option<DecryptedVault>,
    session_key: Option<Zeroizing<Vec<u8>>>,
    kdf: Option<KdfConfig>,
}

impl VaultRuntime {
    fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            decrypted_vault: None,
            session_key: None,
            kdf: None,
        }
    }

    fn initialized(&self) -> bool {
        self.vault_path.exists()
    }

    fn unlocked(&self) -> bool {
        self.decrypted_vault.is_some() && self.session_key.is_some() && self.kdf.is_some()
    }

    fn clear_session(&mut self) {
        if let Some(mut vault) = self.decrypted_vault.take() {
            vault.zeroize();
        }
        self.session_key = None;
        self.kdf = None;
    }
}

struct AppState {
    runtime: Mutex<VaultRuntime>,
}

impl AppState {
    fn new(vault_path: PathBuf) -> Self {
        Self {
            runtime: Mutex::new(VaultRuntime::new(vault_path)),
        }
    }
}

enum MasterHashVerification {
    Verified,
    Missing,
}

impl KdfConfig {
    fn new_random() -> Result<Self, String> {
        let mut salt = [0_u8; 16];
        fill_random_bytes(&mut salt)?;
        Ok(Self {
            salt_b64: URL_SAFE_NO_PAD.encode(salt),
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        })
    }

    fn salt_bytes(&self) -> Result<Vec<u8>, String> {
        URL_SAFE_NO_PAD
            .decode(self.salt_b64.as_bytes())
            .map_err(|_| "KDF salt is invalid.".to_string())
    }
}

#[tauri::command]
fn get_app_status(state: State<'_, AppState>) -> Result<AppStatus, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    Ok(AppStatus {
        initialized: runtime.initialized(),
        unlocked: runtime.unlocked(),
    })
}

#[tauri::command]
fn initialize_master_password(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<Vec<PasswordEntry>, String> {
    let mut master_password = Zeroizing::new(master_password);
    validate_master_password(master_password.as_str())?;

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    if runtime.initialized() {
        return Err("Vault is already initialized.".to_string());
    }

    let kdf = KdfConfig::new_random()?;
    let key = derive_key(master_password.as_str(), &kdf)?;
    let timestamp = now_timestamp();
    let vault = DecryptedVault {
        entries: Vec::new(),
        created_at: timestamp,
        updated_at: timestamp,
    };

    store_master_hash(master_password.as_str())?;
    let encrypted = encrypt_vault(&vault, &key, &kdf)?;
    save_encrypted_vault(&runtime.vault_path, &encrypted)?;

    runtime.clear_session();
    runtime.decrypted_vault = Some(vault);
    runtime.session_key = Some(Zeroizing::new(key.to_vec()));
    runtime.kdf = Some(kdf);
    master_password.zeroize();

    Ok(Vec::new())
}

#[tauri::command]
fn login(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<Vec<PasswordEntry>, String> {
    let mut master_password = Zeroizing::new(master_password);
    validate_master_password(master_password.as_str())?;

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    if !runtime.initialized() {
        return Err("Vault is not initialized yet.".to_string());
    }

    let verification_status = verify_master_hash(master_password.as_str())?;
    let encrypted = load_encrypted_vault(&runtime.vault_path)?;
    validate_kdf_config(&encrypted.kdf)?;
    let key = derive_key(master_password.as_str(), &encrypted.kdf)?;
    let vault = decrypt_vault(&encrypted, &key)?;

    if matches!(verification_status, MasterHashVerification::Missing) {
        store_master_hash(master_password.as_str())?;
    }

    let entries = vault.entries.clone();
    runtime.clear_session();
    runtime.decrypted_vault = Some(vault);
    runtime.session_key = Some(Zeroizing::new(key.to_vec()));
    runtime.kdf = Some(encrypted.kdf);
    master_password.zeroize();

    Ok(entries)
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    runtime.clear_session();
    Ok(())
}

#[tauri::command]
fn get_entries(state: State<'_, AppState>) -> Result<Vec<PasswordEntry>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    let vault = runtime
        .decrypted_vault
        .as_ref()
        .ok_or_else(|| "Vault is locked.".to_string())?;

    Ok(vault.entries.clone())
}

#[tauri::command]
fn add_entry(state: State<'_, AppState>, input: EntryInput) -> Result<PasswordEntry, String> {
    validate_entry_input(&input)?;

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    let timestamp = now_timestamp();
    let entry = PasswordEntry {
        id: generate_identifier()?,
        service: input.service.trim().to_string(),
        username: input.username.trim().to_string(),
        password: input.password,
        notes: input.notes.trim().to_string(),
        url: input.url.trim().to_string(),
        created_at: timestamp,
        updated_at: timestamp,
    };

    let vault = runtime
        .decrypted_vault
        .as_mut()
        .ok_or_else(|| "Vault is locked.".to_string())?;
    vault.entries.push(entry.clone());
    vault.updated_at = timestamp;
    persist_unlocked_vault(&mut runtime)?;

    Ok(entry)
}

#[tauri::command]
fn update_entry(
    state: State<'_, AppState>,
    input: UpdateEntryInput,
) -> Result<PasswordEntry, String> {
    if input.id.trim().is_empty() {
        return Err("Entry ID is required.".to_string());
    }

    validate_entry_input(&EntryInput {
        service: input.service.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        notes: input.notes.clone(),
        url: input.url.clone(),
    })?;

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;
    let vault = runtime
        .decrypted_vault
        .as_mut()
        .ok_or_else(|| "Vault is locked.".to_string())?;

    let item = vault
        .entries
        .iter_mut()
        .find(|candidate| candidate.id == input.id)
        .ok_or_else(|| "Entry was not found.".to_string())?;

    item.service = input.service.trim().to_string();
    item.username = input.username.trim().to_string();
    item.password = input.password;
    item.notes = input.notes.trim().to_string();
    item.url = input.url.trim().to_string();
    item.updated_at = now_timestamp();
    vault.updated_at = item.updated_at;
    let updated = item.clone();

    persist_unlocked_vault(&mut runtime)?;
    Ok(updated)
}

#[tauri::command]
fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), String> {
    if id.trim().is_empty() {
        return Err("Entry ID is required.".to_string());
    }

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;
    let vault = runtime
        .decrypted_vault
        .as_mut()
        .ok_or_else(|| "Vault is locked.".to_string())?;

    let before_len = vault.entries.len();
    vault.entries.retain(|entry| entry.id != id);
    if before_len == vault.entries.len() {
        return Err("Entry was not found.".to_string());
    }

    vault.updated_at = now_timestamp();
    persist_unlocked_vault(&mut runtime)
}

#[tauri::command]
fn generate_password(request: PasswordGenerationRequest) -> Result<String, String> {
    let length = usize::from(request.length);
    if !(12..=24).contains(&length) {
        return Err("Password length must be between 12 and 24 characters.".to_string());
    }

    let lowercase = b"abcdefghijkmnopqrstuvwxyz";
    let uppercase = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    let numbers = b"23456789";
    let symbols = b"!@#$%^&*()-_=+[]{}:,.?";

    let mut groups: Vec<&[u8]> = vec![lowercase, uppercase];
    if request.include_numbers {
        groups.push(numbers);
    }
    if request.include_symbols {
        groups.push(symbols);
    }

    if groups.len() > length {
        return Err("Password length is too short for the selected character sets.".to_string());
    }

    let mut all_chars = Vec::new();
    for group in &groups {
        all_chars.extend_from_slice(group);
    }

    let mut bytes = Vec::with_capacity(length);
    for group in &groups {
        let idx = random_index(group.len())?;
        bytes.push(group[idx]);
    }

    while bytes.len() < length {
        let idx = random_index(all_chars.len())?;
        bytes.push(all_chars[idx]);
    }

    fisher_yates_shuffle(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| "Generated password is invalid UTF-8.".to_string())
}

#[tauri::command]
fn export_encrypted_data(state: State<'_, AppState>) -> Result<String, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    if !runtime.initialized() {
        return Err("Vault is not initialized yet.".to_string());
    }

    fs::read_to_string(&runtime.vault_path)
        .map_err(|error| format!("Cannot read encrypted vault: {error}"))
}

#[tauri::command]
fn import_encrypted_data(
    state: State<'_, AppState>,
    encrypted_json: String,
    master_password: String,
) -> Result<Vec<PasswordEntry>, String> {
    let mut master_password = Zeroizing::new(master_password);
    validate_master_password(master_password.as_str())?;

    let encrypted: EncryptedVaultFile = serde_json::from_str(&encrypted_json)
        .map_err(|_| "Imported file is not a valid encrypted vault.".to_string())?;
    validate_kdf_config(&encrypted.kdf)?;

    let key = derive_key(master_password.as_str(), &encrypted.kdf)?;
    let vault = decrypt_vault(&encrypted, &key)?;
    let entries = vault.entries.clone();

    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Cannot access application state.".to_string())?;

    save_encrypted_vault(&runtime.vault_path, &encrypted)?;
    store_master_hash(master_password.as_str())?;

    runtime.clear_session();
    runtime.decrypted_vault = Some(vault);
    runtime.session_key = Some(Zeroizing::new(key.to_vec()));
    runtime.kdf = Some(encrypted.kdf);
    master_password.zeroize();

    Ok(entries)
}

fn validate_master_password(master_password: &str) -> Result<(), String> {
    if master_password.len() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(format!(
            "Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters long."
        ));
    }
    Ok(())
}

fn validate_entry_input(input: &EntryInput) -> Result<(), String> {
    if input.service.trim().is_empty() {
        return Err("Service name is required.".to_string());
    }

    if input.password.is_empty() {
        return Err("Password cannot be empty.".to_string());
    }

    Ok(())
}

fn validate_kdf_config(kdf: &KdfConfig) -> Result<(), String> {
    if !(19_456..=1_048_576).contains(&kdf.memory_kib) {
        return Err("Invalid Argon2 memory setting in vault file.".to_string());
    }
    if !(1..=10).contains(&kdf.iterations) {
        return Err("Invalid Argon2 iteration setting in vault file.".to_string());
    }
    if !(1..=8).contains(&kdf.parallelism) {
        return Err("Invalid Argon2 parallelism setting in vault file.".to_string());
    }
    Ok(())
}

fn derive_key(master_password: &str, kdf: &KdfConfig) -> Result<[u8; AES_KEY_LENGTH], String> {
    validate_kdf_config(kdf)?;
    let salt = kdf.salt_bytes()?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(AES_KEY_LENGTH),
    )
    .map_err(|error| format!("Cannot prepare Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; AES_KEY_LENGTH];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut key)
        .map_err(|_| "Could not derive encryption key from master password.".to_string())?;
    Ok(key)
}

fn encrypt_vault(
    vault: &DecryptedVault,
    key: &[u8; AES_KEY_LENGTH],
    kdf: &KdfConfig,
) -> Result<EncryptedVaultFile, String> {
    let plaintext = serde_json::to_vec(vault)
        .map_err(|error| format!("Vault serialization failed: {error}"))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES key is invalid.".to_string())?;

    let mut nonce = [0_u8; AES_NONCE_LENGTH];
    fill_random_bytes(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "Vault encryption failed.".to_string())?;

    Ok(EncryptedVaultFile {
        version: 1,
        kdf: kdf.clone(),
        nonce_b64: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext_b64: URL_SAFE_NO_PAD.encode(ciphertext),
        updated_at: now_timestamp(),
    })
}

fn decrypt_vault(
    encrypted: &EncryptedVaultFile,
    key: &[u8; AES_KEY_LENGTH],
) -> Result<DecryptedVault, String> {
    if encrypted.version != 1 {
        return Err("Unsupported vault version.".to_string());
    }

    let nonce = URL_SAFE_NO_PAD
        .decode(encrypted.nonce_b64.as_bytes())
        .map_err(|_| "Vault nonce is invalid.".to_string())?;
    if nonce.len() != AES_NONCE_LENGTH {
        return Err("Vault nonce has invalid length.".to_string());
    }

    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted.ciphertext_b64.as_bytes())
        .map_err(|_| "Vault ciphertext is invalid.".to_string())?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES key is invalid.".to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Master password is incorrect or vault has been tampered with.".to_string())?;

    serde_json::from_slice::<DecryptedVault>(&plaintext)
        .map_err(|_| "Vault payload is corrupted.".to_string())
}

fn save_encrypted_vault(path: &Path, encrypted: &EncryptedVaultFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Cannot create vault directory: {error}"))?;
    }

    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|error| format!("Vault serialization failed: {error}"))?;
    fs::write(path, json).map_err(|error| format!("Cannot persist encrypted vault: {error}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn load_encrypted_vault(path: &Path) -> Result<EncryptedVaultFile, String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("Cannot read encrypted vault: {error}"))?;
    serde_json::from_str::<EncryptedVaultFile>(&json)
        .map_err(|_| "Encrypted vault file is corrupted.".to_string())
}

fn persist_unlocked_vault(runtime: &mut VaultRuntime) -> Result<(), String> {
    let vault = runtime
        .decrypted_vault
        .as_ref()
        .ok_or_else(|| "Vault is locked.".to_string())?;
    let key = runtime
        .session_key
        .as_ref()
        .ok_or_else(|| "Vault is locked.".to_string())?;
    let kdf = runtime
        .kdf
        .as_ref()
        .ok_or_else(|| "Vault key configuration is missing.".to_string())?;

    if key.len() != AES_KEY_LENGTH {
        return Err("Session key has invalid length.".to_string());
    }

    let mut key_array = [0_u8; AES_KEY_LENGTH];
    key_array.copy_from_slice(key.as_slice());
    let encrypted = encrypt_vault(vault, &key_array, kdf)?;
    save_encrypted_vault(&runtime.vault_path, &encrypted)
}

fn keyring_entry() -> Result<KeyringEntry, String> {
    KeyringEntry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|error| format!("Keyring initialization failed: {error}"))
}

fn store_master_hash(master_password: &str) -> Result<(), String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(master_password.as_bytes(), &salt)
        .map_err(|error| format!("Master password hashing failed: {error}"))?
        .to_string();

    keyring_entry()?
        .set_password(&hash)
        .map_err(|error| format!("Cannot store authentication data in keyring: {error}"))
}

fn verify_master_hash(master_password: &str) -> Result<MasterHashVerification, String> {
    let entry = keyring_entry()?;
    let stored_hash = match entry.get_password() {
        Ok(value) => value,
        Err(KeyringError::NoEntry) => return Ok(MasterHashVerification::Missing),
        Err(error) => {
            return Err(format!(
                "Cannot read authentication data from keyring: {error}"
            ))
        }
    };

    let parsed_hash = PasswordHash::new(&stored_hash)
        .map_err(|error| format!("Stored password hash is invalid: {error}"))?;

    Argon2::default()
        .verify_password(master_password.as_bytes(), &parsed_hash)
        .map_err(|_| "Master password is incorrect.".to_string())?;

    Ok(MasterHashVerification::Verified)
}

fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn fill_random_bytes(buffer: &mut [u8]) -> Result<(), String> {
    SystemRandom::new()
        .fill(buffer)
        .map_err(|_| "Secure random generator failed.".to_string())
}

fn random_u32() -> Result<u32, String> {
    let mut bytes = [0_u8; 4];
    fill_random_bytes(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn random_index(max: usize) -> Result<usize, String> {
    if max == 0 {
        return Err("Random index upper bound cannot be zero.".to_string());
    }

    let upper_bound = max as u32;
    let limit = u32::MAX - (u32::MAX % upper_bound);
    loop {
        let value = random_u32()?;
        if value < limit {
            return Ok((value % upper_bound) as usize);
        }
    }
}

fn fisher_yates_shuffle(bytes: &mut [u8]) -> Result<(), String> {
    if bytes.len() <= 1 {
        return Ok(());
    }

    for index in (1..bytes.len()).rev() {
        let swap_index = random_index(index + 1)?;
        bytes.swap(index, swap_index);
    }
    Ok(())
}

fn generate_identifier() -> Result<String, String> {
    let mut bytes = [0_u8; 18];
    fill_random_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let mut vault_path = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("Cannot resolve application data directory: {error}"))?;
            vault_path.push(VAULT_FILE_NAME);
            app.manage(AppState::new(vault_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_status,
            initialize_master_password,
            login,
            lock_vault,
            get_entries,
            add_entry,
            update_entry,
            delete_entry,
            generate_password,
            export_encrypted_data,
            import_encrypted_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
