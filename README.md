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
- **Cross-platform:** Native path handling across Windows, macOS, and Linux, including Windows verbatim (`\\?\`) prefixes and drive letters.

---

## Installation

### Pre-compiled Binaries

Download the latest release for your platform from the **GitHub Releases** or **Actions** tab:

| Platform | Binary |
| :--- | :--- |
| **Linux (x86_64)** | `encr-linux` |
| **macOS (Universal / Apple Silicon)** | `encr-macos` |
| **Windows (x64)** | `encr-windows.exe` |

On Linux and macOS, make the downloaded binary executable and move it into your `PATH`:

```bash
chmod +x encr-linux
sudo mv encr-linux /usr/local/bin/encr
```

### Build From Source

Requires a working [Rust toolchain](https://rustup.rs/) (1.85+):

```bash
cargo install --path .
```

Or build an optimized release binary manually:

```bash
cargo build --release --locked
# Binary is located at target/release/encr
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

### 2. Encrypting Files and Directories

Encrypt a single file using a generated key:

```bash
encr encrypt \
  --input database.sqlite \
  --output database.sqlite.enc \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

Encrypt a directory. It will be compressed (`zstd`) and encrypted in a single stream:

```bash
encr encrypt \
  --input ./project-backup \
  --output project-backup.enc \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

Encrypt using a passphrase prompted interactively (no key on the command line):

```bash
encr encrypt -i ./photos -o photos.enc
# Key or passphrase: 
# Confirm: 
```

Encrypt using an environment variable (useful in scripts and CI/CD):

```bash
export ENCR_KEY="correct horse battery staple"
encr encrypt -i dataset.csv -o dataset.csv.enc
```

Adjust the compression level for a directory archive (1–19, default: 3):

```bash
encr encrypt -i ./logs -o logs.enc --compression-level 9
```

### 3. Inspecting Archives Without Decrypting to Disk (`show`)

Inspect the contents and verify the authentication tag of an encrypted directory without writing any files to disk:

```bash
encr show --input project-backup.enc --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

Output:

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

### 4. Decrypting

Decrypt a file or restore an entire directory tree:

```bash
encr decrypt \
  --input project-backup.enc \
  --output ./restored-project \
  --key "pxaAkP64TeMYzDHi1VgkrYc4-eQnJhgm1r0yb51d7FY"
```

Overwrite an existing file or merge into an existing directory:

```bash
encr decrypt -i database.sqlite.enc -o database.sqlite --force
```

---

## License

This project is dual-licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](http://opensource.org/licenses/MIT)

at your option.
