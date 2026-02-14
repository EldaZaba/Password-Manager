# PasswordManager

Local desktop password manager built with Tauri v2, React, and Rust.
All data stays on your device and the vault is encrypted.

## Main Features

- Create and unlock a vault with a master password.
- Master password minimum length: 12 characters.
- Store credentials in a local encrypted vault.
- Full CRUD for entries: add, edit, delete.
- Search and sorting (A-Z, Z-A, last updated).
- Password generator (length 12-24, optional numbers/symbols).
- Copy password to clipboard with automatic wipe after 30 seconds.
- Auto-lock after 5 minutes of inactivity.
- Export/import encrypted vault data (JSON).
- Light/Dark theme.

## Security

- Vault encryption: `AES-256-GCM`.
- Key derivation from master password: `Argon2id`.
- Master password hash is stored in the system keyring.
- Sensitive data is kept in memory only while the vault is unlocked.
- Import replaces the local vault file.

## Tech Stack

- Frontend: React 19 + TypeScript + Vite + Tailwind CSS
- Desktop runtime: Tauri v2
- Backend: Rust
- Cryptography: `aes-gcm`, `argon2`, `ring`, `zeroize`

## Requirements

- Node.js 20+ and `npm`
- Rust toolchain (stable) + `cargo`
- System dependencies for Tauri:
  https://tauri.app/start/prerequisites/

## Installation

```bash
npm install
```

## Development

Run the full desktop app (frontend + Tauri):

```bash
npm run tauri dev
```

Run frontend only (without Tauri backend):

```bash
npm run dev
```

## Build

Frontend build:

```bash
npm run build
```

Desktop build (installer/binary):

```bash
npm run tauri build
```

## Project Structure

- `src/` - React UI
- `src-tauri/src/lib.rs` - Rust logic (encryption, vault, Tauri commands)
- `src-tauri/tauri.conf.json` - Tauri configuration
- `assets/icon.png` - project icon source

## License

MIT (`LICENSE`)
