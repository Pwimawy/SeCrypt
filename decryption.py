import os
import sys
import argparse
import getpass
import json
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrypt_utils import decrypt_with_password


# === Constants ===
LOG_PATH = Path.home() / ".decryption.log"
LOG_PERMISSIONS = 0o600


# === Logging Utilities ===
def _ensure_log():
    if not LOG_PATH.exists():
        with open(LOG_PATH, "a", encoding="utf-8"):
            pass
        try:
            os.chmod(LOG_PATH, LOG_PERMISSIONS)
        except Exception:
            pass


def _log_event(enc_path: str, keyfile_path: str, status: str, message: str = ""):
    _ensure_log()
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "encrypted_file": enc_path,
        "keyfile": keyfile_path,
        "status": status,
        "message": message,
    }
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


# === Core Functions ===
def decrypt_file(enc_path: Path, keyfile_path: Path, password: bytes) -> Path:
    with open(keyfile_path, "r", encoding="utf-8") as f:
        keyfile_data = json.load(f)

    enc_info = keyfile_data["file_key_encrypted"]
    metadata = keyfile_data.get("metadata", {})
    original_filename = metadata.get("original_filename", "decrypted_output")

    file_key = decrypt_with_password(enc_info, password)

    with open(enc_path, "rb") as f:
        nonce = f.read(12)
        ciphertext = f.read()

    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    out_dir = Path("decrypted_files")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / original_filename

    with open(out_path, "wb") as f_out:
        f_out.write(plaintext)

    return out_path


# === Main Entry Point ===
def main():
    parser = argparse.ArgumentParser(
        description="File Decryption Utility — CLI only (silent).",
        usage="decryption.py --decrypt <file.enc> --keyfile <file.key.json> [--password <password>]",
    )
    parser.add_argument("--decrypt", dest="infile", required=True, help="Path to encrypted file (.enc)")
    parser.add_argument("--keyfile", dest="keyfile", required=True, help="Path to keyfile (.key.json)")
    parser.add_argument("--password", dest="password", help="Decryption password (optional)")
    args = parser.parse_args()

    enc_path = Path(args.infile).expanduser()
    keyfile_path = Path(args.keyfile).expanduser()

    if not enc_path.exists():
        _log_event(str(enc_path), str(keyfile_path), "failure", "encrypted file not found")
        sys.exit(1)

    if not keyfile_path.exists():
        _log_event(str(enc_path), str(keyfile_path), "failure", "keyfile not found")
        sys.exit(1)

    password = args.password.encode() if args.password else getpass.getpass("Password: ").encode()

    try:
        out_path = decrypt_file(enc_path, keyfile_path, password)
        _log_event(str(enc_path), str(keyfile_path), "success", f"decrypted to {str(out_path)}")
        sys.exit(0)
    except Exception as e:
        err_msg = getattr(e, "args", (str(e),))[0]
        _log_event(str(enc_path), str(keyfile_path), "failure", str(err_msg))
        sys.exit(1)


if __name__ == "__main__":
    main()
