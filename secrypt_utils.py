import json
import secrets
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === Constants ===
PBKDF2_ITERATIONS = 200_000
AES_KEY_SIZE = 32            # 256-bit AES key
AES_NONCE_SIZE = 12          # 96-bit GCM nonce
FILE_KEY_SIZE = 32           # 256-bit random key for each file

# === Key Derivation ===
def derive_key_from_password(password: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

# === Password-Based Encryption ===
def encrypt_with_password(data: bytes, password: bytes) -> dict:
    """Encrypt arbitrary data (e.g., file key) using AES-GCM with a derived key."""
    salt = secrets.token_bytes(16)
    key = derive_key_from_password(password, salt)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {
        "salt": b64encode(salt).decode(),
        "nonce": b64encode(nonce).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
    }

def decrypt_with_password(enc_dict: dict, password: bytes) -> bytes:
    """Decrypt data that was encrypted with encrypt_with_password()."""
    salt = b64decode(enc_dict["salt"])
    nonce = b64decode(enc_dict["nonce"])
    ciphertext = b64decode(enc_dict["ciphertext"])
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# === File Encryption ===
def encrypt_file_with_key(in_path, out_path, file_key: bytes):
    """Encrypt a file using AES-GCM with the provided file key."""
    aesgcm = AESGCM(file_key)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    with open(in_path, "rb") as f_in:
        plaintext = f_in.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(out_path, "wb") as f_out:
        f_out.write(nonce + ciphertext)

# === Keyfile Management ===
def create_keyfile(file_key: bytes, password: bytes, keyfile_path, metadata: dict):
    """Encrypt the file key with a password and store it in a JSON keyfile."""
    enc_data = encrypt_with_password(file_key, password)
    keyfile_data = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "file_key_encrypted": enc_data,
        "metadata": metadata,
    }
    with open(keyfile_path, "w") as f:
        json.dump(keyfile_data, f, indent=4)

# === Module Check ===
if __name__ == "__main__":
    print("✅ secrypt_utils.py (cryptography version) loaded successfully.")
