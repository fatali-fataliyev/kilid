# [Logo](./docs/images/cover.png)

## Kilid 🔐

**Kilid** is a minimalist, high-performance CLI tool designed to protect your **sensitive files using AES Military-Grade Encryption**.
Everything stays on your machine.

---

### 🚀 Key Features

- **AES Encryption:** Industry-standard protection for your data.
- **Zero Trust:** Kilid itself does not have any idea about your password, only you know.
- **Built-in Safety:** Mandatory password hints to prevent permanent data loss (perfect for the ADHD-brained among us! 🧠).
- **Privacy First:** Works 100% offline.

---

### 🛠 How it Works

1. **Input:** Pass your files to Kilid.
2. **Secure:** Set a strong password.
3. **Hint:** Create a mandatory password hint (highly recommended since lost passwords **cannot** be recovered).
4. **Result:** Your file is transformed into a secure `.kld` vault.

---

### 📦 Installation

#### 1. Via Go (Recommended)

If you have Go installed, run:

```bash
    go install github.com/fatali-fataliyev/kilid@latest
```

**Note**: Verify by typing `kilid -h`

#### 2. Pre-compiled Binaries

#### Download the latest executable for your OS from the [Releases page](xxx).

---

### 💻 Usage Guide

#### 1. Encrypt a File

```bash
    kilid enc secret.txt
```

<i>**You will be prompted to enter a password and a hint.**</i>

#### 2. Decrypt a File

```bash
    kilid dec secret.kld
```

#### 3. Inspect Metadata

**View file details without decrypting them**

```bash
    kilid info secret.kld
```

**Exmaple output**:

```
─── File Details: gizli.kld ───
Original Extension   : .txt
Password Hint        : tubu
Encrypted At         : 2026-04-05 09:53:34
Kilid Version        : 1.0.0
─────────────────────────────────────────────
```

### 4. 🪛 Advanced Flags

- **Delete Source (-d, --delete)**: Automatically wipes the original file, so use with caution.

```bash
kilid enc passwords.txt -d
```

**Creates passwords.kld and deletes passwords.txt**

```bash
kilid dec passwords.kld -d
```

**Creates passwords.txt and deletes passwords.kld**

- **Auto-Confirm (-y, --yes):** Automatically overwrites existing files during decryption.

```bash
kld dec secret.kld -y
```

**If there is a file named secret.txt when decryption its value will be overwrite**

---

### 🤝 Contributing & Feedback

#### If you have any idea/improvment feel free to open an issue or join project.

### ❤️ Special Thanks

Big thanks to [Sanan R. Fataliyev](abc.com) for the architectural design help!
