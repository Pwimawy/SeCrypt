# 🔐 Secrypt — Secure File Encryption & Decryption (CLI)

Secrypt is a simple yet strong command-line file encryption tool built in Python using the **`cryptography`** library.  
It encrypts your files with AES-256-GCM and protects the encryption key using a password-based keyfile system.  
No GUI — no leaks — just pure encryption.

 ______     ______     ______     ______     __  __     ______   ______  
/\  ___\   /\  ___\   /\  ___\   /\  == \   /\ \_\ \   /\  == \ /\__  _\ 
\ \___  \  \ \  __\   \ \ \____  \ \  __<   \ \____ \  \ \  _-/ \/_/\ \/ 
 \/\_____\  \ \_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_\      \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_/ /_/   \/_____/   \/_/       \/_/ 
                                                                         
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
```
python secrypt.py --encrypt <file>
```

You will be prompted for a password (hidden input).  

### Optional Password Argument  
```
python secrypt.py --encrypt <file> --password "<yourpassword>"
```

### Output Files  
- Encrypted file → `encrypted_files/<filename>.enc`  
- Keyfile → `keyfiles/<filename>.key.json`  

🧠 **Important:** Keep your password and keyfile safe. You need both to decrypt.

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
secrypt/
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
- Uses **AES-256-GCM** (authenticated encryption)
- Passwords are never stored in plaintext  
- Keyfiles contain encrypted file keys using PBKDF2-derived keys  
- No GUI = minimal attack surface  
- Hidden logs track encryption events locally  

---

## 🧑‍💻 Example Workflow

```
# Encrypt a file
python secrypt.py --encrypt secret.txt

# Decrypt it
python decryption.py --decrypt encrypted_files/secret.txt.enc --keyfile keyfiles/secret.txt.key.json
```

---

## 📜 License
MIT License © 2025 — Made by **Pwimawy**

git clone https://github.com/<your-username>/secrypt.git
cd secrypt
