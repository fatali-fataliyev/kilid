<p align="center">
  <img src="./docs/images/cover.png" alt="Kilid Logo" width="400">
</p>

<h1 align="center">Kilid 🔐</h1>

**Kilid** is a minimalist, high-performance CLI tool designed to protect your **sensitive files using AES Military-Grade Encryption**.

---

### 🚀 Key Features

- **Encryption:** Kilid using strong <i>AES</i> encryption for maximum security.
- **Transparency:** Kilid never see or store your password. Only you know.
- **Hint:** Integrated password hints to prevent accidental password forget.
- **Privacy:** 100% local execution, Everything stays on your machine.
- **Tamper-Proof:** Automatic integrity checks block access if encrypted data is altered.

---

### 🛠 How it Works

1. **Input:** Pass your files to Kilid.
2. **Secure:** Set a strong password.
3. **Hint:** Create a password hint (HIGHLY recommended since lost passwords **cannot** be recovered).
4. **Result:** Your file is transformed into a secure `.kld` vault.

---

### 📦 Installation

#### 1. Via Go (Recommended)

If you have Go installed, run:

```bash
go install github.com/fatali-fataliyev/kilid/v3@latest
```

**Note**: Verify by typing `kilid version`

#### 2. Pre-compiled Binaries

#### Download the latest executable for your OS from the [Releases Page](https://github.com/fatali-fataliyev/kilid/releases)

---

### 💻 Usage Guide

#### 1. Encrypt a File

```bash
kilid enc secret.txt
```

<i>**You will be prompted to enter confirm password and a password hint.**</i>

#### 2. Decrypt a File

```bash
kilid dec secret.kld
```

#### 3. Inspect Metadata

**View file details without decrypting them**

```bash
kilid info secret.kld
```

**Example output**:

```
─── File Details: secret.kld ───
Original Extension   : .txt
Password Hint        : tubu
Encrypted At         : 2026-04-05 09:53:34
Kilid Version        : 1.0.0
─────────────────────────────────────────────
```

### 4. 🪛 Advanced Flags

- **Delete Source (-d, --delete)**: Removes the source file after `enc` or `dec` operation.

```bash
# Encrypts and deletes original .txt
kilid enc passwords.txt -d

# Decrypts and deletes encrypted .kld
kilid dec passwords.kld -d
```

- **Auto-Confirm (-y, --yes):** Automatically overwrites existing files during decryption/encryption.

```bash
# Force overwrite if secret.txt already exists
kilid dec secret.kld -y
```

- **Source file wipe (-wipe)**: Wipes source files after encryption to prevent restoration via recovery software.
  <i>
  **Note**: This operation can take several minutes depending on the file size</i>. If you want to just remove the source file, use the `--delete` flag instead of `-wipe`

```bash
kilid enc passwords.txt -wipe
```

---

### What’s New in v3

- Replaced SHA256 with Argon2id to prevent brute-force and rainbow table risks.
- Password confirmation prompt to prevent typos.
- Added `-wipe` feature to shred source files after **encryption**, preventing data recovery.
- Modernized progress bar style and added ETA in seconds.
- Graceful shutdown prevents incomplete encryption/decryption processes

> See [full history](./CHANGELOG.md)

### 🧪 Tested On

| Platform       | Status    | Architecture |
| :------------- | :-------- | :----------- |
| **Windows 11** | ✅ Tested | amd64        |
| **Linux**      | ✅ Tested | amd64        |
| **macOS**      | ✅ Tested | arm64        |

---

### 🤝 Contributing & Feedback

#### If you have any idea/improvement feel free to open an issue or join the project.

---

## ❤️ Special Thanks

Big thanks to [Sanan R. Fataliyev](https://github.com/sanan-fataliyev) for the architectural design help!

/// Todo: Graceful shutdown, close half enc/dec files.
