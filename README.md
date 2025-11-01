# 🔐 Secrypt — Secure File Encryption & Decryption (CLI)

Secrypt is a simple yet strong command-line file encryption tool built in Python using the **`cryptography`** library.  
It encrypts your files with AES-256-GCM and protects the encryption key using a password-based keyfile system.  
No GUI — no leaks — just pure encryption.

~~~text
 ______     ______     ______     ______     __  __     ______   ______  
/\  ___\   /\  ___\   /\  ___\   /\  == \   /\ \_\ \   /\  == \ /\__  _\ 
\ \___  \  \ \  __\   \ \ \____  \ \  __<   \ \____ \  \ \  _-/ \/_/\ \/ 
 \/\_____\  \ \_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_\      \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_/ /_/   \/_____/   \/_/       \/_/
~~~
                                                                         
                          ***made by Pwimawy***

---

## ⚙️ Features
- AES-256-GCM encryption  
- Password-derived keyfile protection  
- Hidden logs for tamper tracking  
- Simple CLI interface  
- No dependencies beyond `cryptography`

---

## 📦 1. Installation

### Option A — Clone from GitHub  
```
git clone https://github.com/Pwimawy/SeCrypt.git
cd SeCrypt
```

### Option B — Manual Download  
1. Click **Code → Download ZIP**  
2. Extract it anywhere  
3. Open a terminal in that folder  

### Install Dependencies  
```
pip install cryptography
```

---

## 🔑 2. Encryption

### Basic Usage

~~~bash
python secrypt.py
~~~

1. **Run the script**:
```
python secrypt.py
```

2. **Follow the on-screen prompts**:
- You will see the SECRYPT ASCII banner.
- A menu will appear with options:
  1. Encrypt a file
  2. Open `encrypted_files` folder
  3. Open `keyfiles` folder
  4. Exit

3. **Encrypt a file**:
- Choose option `[1] Encrypt a file`.
- Enter the path to the file you want to encrypt.
- Enter an encryption password (hidden input if left blank).
- The encrypted file will be saved in `encrypted_files/`.
- The keyfile required for decryption will be saved in `keyfiles/`.

4. **Other actions**:
- Open folders using options `[2]` or `[3]`.
- Exit the utility with option `[4]`.

### Output Files

When you encrypt a file using SECRYPT, two main output files are generated:

1. **Encrypted File**  
   - Location: `encrypted_files/`  
   - Filename: `<original_filename>.enc`  
   - This is the actual encrypted version of your file.  
   - Example: If you encrypt `document.txt`, the encrypted file will be `encrypted_files/document.txt.enc`.

2. **Keyfile**  
   - Location: `keyfiles/`  
   - Filename: `<original_filename>.key.json`  
   - This JSON file contains the encrypted file key and metadata needed for decryption.  
   - Example: For `document.txt`, the keyfile will be `keyfiles/document.txt.key.json`.

⚠️ **Important**: Both the encrypted file and its corresponding keyfile are required to successfully decrypt your data. Never lose or share your password and keyfile.

---

## 🔓 3. Decryption

### Basic Usage  
```
python decryption.py --decrypt <encrypted_file> --keyfile <keyfile.json>
```

You’ll be prompted for the password used during encryption.  

### Optional Password Argument  
```
python decryption.py --decrypt <encrypted_file> --keyfile <keyfile.json> --password "<yourpassword>"
```

### Output  
The original file will be restored in the current directory.

---

## 🧰 4. File Structure

```
SeCrypt/
├── secrypt.py
├── decryption.py
├── secrypt_utils.py
├── encrypted_files/
└── keyfiles/
```

No need to include:
- `__pycache__/`
- `.venv/`
- `.env` or temporary test files

---

## 🛡️ 5. Security Notes

- Uses **AES-256-GCM** (authenticated encryption).  
- Passwords are never stored in plaintext.  
- Keyfiles contain encrypted file keys derived from user passwords (PBKDF2 or similar).  
- **GUI / TUI present** — the project includes an interactive text-based GUI. This improves usability but increases the attack surface compared to a non-interactive CLI. Treat GUI components as part of the trusted code-path and apply the same hardening and review practices as the rest of the codebase.  
- Be careful with visible password input: the current flow allows either a visible typed password or a hidden prompt (via `getpass`) when left blank — prefer always using hidden input to avoid shoulder-surfing and accidental logging.  
- Opening folders with OS commands (e.g., `os.startfile` / `open`) interacts with the host OS and may expose file paths to the desktop environment — avoid calling these from privileged contexts.  
- Local logs (if enabled) record encryption events on disk — keep logs local, encrypted, or opt them out entirely. Logs may contain filenames and timestamps; do **not** log secrets (passwords, raw keys, or key material).  
- File and keyfile storage:
  - Encrypted files are stored under `encrypted_files/` and keyfiles under `keyfiles/`.  
  - Ensure proper filesystem permissions on these folders (restrict to the user account).  
  - Never store keyfiles or passwords in cloud-sync folders unless they are additionally secured (e.g., full-disk encryption + separate secret management).  
- Backups & key management: losing the keyfile or password means losing access to the data. Keep secure, redundant backups of keyfiles (but keep them protected!).  
- Threat model & best practices:
  - Do not run SECRYPT as an elevated/administrator account unless necessary.  
  - Audit third-party dependencies (e.g., crypto libraries) and keep them up-to-date.  
  - Prefer long, high-entropy passphrases over short passwords. Consider integrating hardware-backed keystores (YubiKey / HSM) for high-security workflows.  
  - Consider secure deletion for original plaintext files after verification (implement carefully; secure deletion is OS-dependent and not currently provided).  
- Recommendations for future hardening:
  - Always use hidden password prompts in the GUI/TUI by default.  
  - Add an option to disable local logging or to encrypt logs.  
  - Add integrity checks and fingerprinting for keyfiles so users can verify they’re using the correct keyfile.  
  - Consider code signing for releases to reduce tampering risk.


---

## 📜 License
MIT License © 2025 — Made by **Pwimawy**

git clone https://github.com/<your-username>/secrypt.git
cd secrypt
