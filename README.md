# encr

Fast, streaming, authenticated encryption for files and directories on Windows, macOS, and Linux.

`encr` is built for encrypting large files and directory trees without running out of memory. It encrypts data in 1 MiB chunks using AES-256-GCM, automatically archives and compresses directories with `tar` and `zstd` before encrypting, and writes output atomically so a failed or interrupted operation never leaves a partial file on disk.

---

## Key Features

- **Constant memory usage:** Streams data through a 1 MiB chunk buffer. Multi-gigabyte files encrypt and decrypt with peak memory under 5 MiB.
- **Hardware-accelerated AES-256-GCM:** Uses AES-NI and ARM Cryptography Extensions where available, authenticated with the STREAM construction to stop truncation, reordering, and bit flips.
- **Automatic directory handling:** Directories are compressed into multithreaded `zstd` tarballs and encrypted in a single pass. Decryption restores the tree.
- **In-memory inspection (`show`):** Decrypts and decompresses archive headers on the fly to list files and sizes without writing anything to disk.
- **Flexible key derivation:** Accepts 256-bit random keys directly, or passphrases stretched with Argon2id. Every file uses a unique HKDF-derived subkey.
- **Atomic writes:** Writes to a hidden staging file or directory, moving it into place only after the full stream authenticates. Refuses to overwrite existing files without `--force`.
- **Cross-platform:** Native path handling across Windows, macOS, and Linux, including Windows verbatim (`\\?\`) prefixes, drive letters (`C:\`), and backslashes.

---

## Installation

### Pre-compiled Binaries

Download the latest release for your platform from the **GitHub Releases** or **Actions** tab:

| Platform | Binary |
| :--- | :--- |
| **Windows (x64)** | `encr-windows.exe` |
| **Linux (x86_64)** | `encr-linux` |
| **macOS (Universal / Apple Silicon)** | `encr-macos` |

#### Linux & macOS

Make the downloaded binary executable and move it into your `PATH`:

```bash
chmod +x encr-linux
sudo mv encr-linux /usr/local/bin/encr
```

#### Windows (PowerShell)

1. Rename the downloaded `encr-windows.exe` to `encr.exe`.
2. Move it to a folder in your `PATH` (such as `$HOME\bin`), or add your folder to the user `PATH`:

```powershell
# Create a user bin folder if it doesn't exist
New-Item -ItemType Directory -Force -Path "$HOME\bin"

# Move and rename the binary into $HOME\bin\encr.exe
Move-Item -Path ".\encr-windows.exe" -Destination "$HOME\bin\encr.exe"

# Add $HOME\bin to your User PATH (one-time setup)
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "User") + ";$HOME\bin",
    "User"
)
$env:Path += ";$HOME\bin"

# Verify installation
encr --version
```

Alternatively, on Windows Command Prompt (`cmd.exe`):
```cmd
mkdir "%USERPROFILE%\bin"
move encr-windows.exe "%USERPROFILE%\bin\encr.exe"
setx PATH "%PATH%;%USERPROFILE%\bin"
```

### Build From Source

Requires a working [Rust toolchain](https://rustup.rs/) (1.85+):

```bash
cargo install --path .
```

Or build an optimized release binary manually:

```bash
cargo build --release --locked
# Linux / macOS: target/release/encr
# Windows:       target\release\encr.exe
```

---

## Usage & Commands

```text
encr <COMMAND>
```

| Command | Description |
| :--- | :--- |
| `encrypt` | Encrypt a single file, or a directory (tarred and compressed). |
| `decrypt` | Decrypt an encrypted file back to the original file or directory. |
| `show` | Decrypt an archive in-memory and list its contents (dry-run). |
| `generate-key` | Generate a cryptographically secure 256-bit base64url key. |
| `generate-password` | Generate a random password with configurable complexity and length. |

### Global Key Options

For commands that require a secret (`encrypt`, `decrypt`, `show`), `encr` resolves the key in this order:

1. `--key <KEY>` (or `-k`) passed directly on the command line.
2. `ENCR_KEY` environment variable.
3. Interactive hidden prompt (with confirmation on `encrypt`).

---

## Examples

### 1. Generating Keys and Passwords

Generate a 256-bit raw session key:

```bash
encr generate-key
# Output: pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY
```

Generate passwords of varying complexity:

```bash
# Weak: lowercase + digits
encr generate-password --level weak --length 16

# Medium: mixed-case + digits
encr generate-password --level medium --length 20

# Strong: mixed-case + digits + shell-safe symbols
encr generate-password --level strong --length 32
```

---

### 2. Encrypting Files and Directories

#### Linux / macOS (bash / zsh)

```bash
# Single file
encr encrypt \
  --input database.sqlite \
  --output database.sqlite.enc \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Entire directory (compressed with zstd and encrypted)
encr encrypt \
  --input ./project-backup \
  --output project-backup.enc \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Prompt interactively for a passphrase (hidden input, no key in shell history)
encr encrypt -i ./photos -o photos.enc

# Using the ENCR_KEY environment variable
export ENCR_KEY="correct horse battery staple"
encr encrypt -i dataset.csv -o dataset.csv.enc
```

#### Windows (PowerShell)

In PowerShell, use backtick (`` ` ``) for multiline commands, standard Windows paths, or `$env:ENCR_KEY`:

```powershell
# Single file
encr.exe encrypt `
  --input "C:\Data\database.sqlite" `
  --output "C:\Backups\database.sqlite.enc" `
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Entire directory
encr.exe encrypt `
  --input ".\project-backup" `
  --output ".\project-backup.enc" `
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Using the ENCR_KEY environment variable in PowerShell
$env:ENCR_KEY = "correct horse battery staple"
encr.exe encrypt -i ".\dataset.csv" -o ".\dataset.csv.enc"
```

#### Windows (Command Prompt / cmd.exe)

In Command Prompt, use caret (`^`) for multiline commands, or `set` for environment variables:

```cmd
:: Using environment variable
set ENCR_KEY=correct horse battery staple
encr.exe encrypt -i C:\Data\dataset.csv -o C:\Backups\dataset.csv.enc

:: Direct command
encr.exe encrypt ^
  --input "C:\Data\project-backup" ^
  --output "C:\Backups\project-backup.enc" ^
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

---

### 3. Inspecting Archives Without Decrypting to Disk (`show`)

Inspect the contents and verify the authentication tag of an encrypted directory without writing any files to disk:

**Linux / macOS:**
```bash
encr show --input project-backup.enc --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

**Windows (PowerShell):**
```powershell
encr.exe show --input ".\project-backup.enc" --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

Sample output:
```text
TYPE        SIZE  PATH
file       1.2 KiB  Cargo.toml
dir            -  src/
file      14.3 KiB  src/main.rs
file       4.8 KiB  src/crypto.rs
link           -  README -> Cargo.toml

4 files, 1 directories, 1 links, 20.3 KiB, integrity verified
```

For single-file payloads, `show` verifies data integrity and prints the plaintext size:
```bash
encr show -i database.sqlite.enc
# Single file: 42.0 MiB (44040192 bytes), integrity verified
```

---

### 4. Decrypting

#### Linux / macOS

```bash
# Decrypt directory archive
encr decrypt \
  --input project-backup.enc \
  --output ./restored-project \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Overwrite existing target with --force
encr decrypt -i database.sqlite.enc -o database.sqlite --force
```

#### Windows (PowerShell / CMD)

```powershell
# Restore directory archive
encr.exe decrypt `
  --input ".\project-backup.enc" `
  --output "C:\Restored\project" `
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"

# Overwrite existing destination with --force
encr.exe decrypt -i ".\database.sqlite.enc" -o "C:\Data\database.sqlite" --force
```

> [!NOTE]
> **Windows Symlinks Note:** If an archive contains Unix symbolic links, extracting those links on Windows requires either **Developer Mode** enabled or running PowerShell / Command Prompt as **Administrator** due to Windows security policies on symlink creation.

---

## License

This project is dual-licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](http://opensource.org/licenses/MIT)

at your option.
