import os
import argparse
import getpass
from pathlib import Path
import secrets
from secrypt_utils import create_keyfile, encrypt_file_with_key

# === Banner ===
ASCII_ART = r"""
 ______     ______     ______     ______     __  __     ______   ______  
/\  ___\   /\  ___\   /\  ___\   /\  == \   /\ \_\ \   /\  == \ /\__  _\ 
\ \___  \  \ \  __\   \ \ \____  \ \  __<   \ \____ \  \ \  _-/ \/_/\ \/ 
 \/\_____\  \ \_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_\      \ \_\ 
  \/_____/   \/_____/   \/_____/   \/_/ /_/   \/_____/   \/_/       \/_/ 
                                                                         
                          made by Pwimawy
"""

# === Directory Setup ===
def ensure_dirs():
    os.makedirs('encrypted_files', exist_ok=True)
    os.makedirs('keyfiles', exist_ok=True)

# === Main Logic ===
def main():
    print(ASCII_ART)

    parser = argparse.ArgumentParser(description='File Encryption Utility (CLI)')
    parser.add_argument('--encrypt', dest='infile', help='Path to file to encrypt')
    parser.add_argument('--password', dest='password', help='Encryption password (optional)')
    args = parser.parse_args()

    if not args.infile:
        print("\nUsage: secrypt.py --encrypt <file> [--password <password>]\n")
        return

    ensure_dirs()
    in_path = Path(args.infile).expanduser()
    if not in_path.exists():
        print("File not found:", in_path)
        return

    password = args.password.encode() if args.password else getpass.getpass("Password: ").encode()
    file_key = secrets.token_bytes(32)

    enc_path = Path("encrypted_files") / (in_path.name + ".enc")
    keyfile_path = Path("keyfiles") / (in_path.name + ".key.json")

    print("\nEncrypting...")
    metadata = {"original_filename": in_path.name}

    encrypt_file_with_key(in_path, enc_path, file_key)
    create_keyfile(file_key, password, keyfile_path, metadata)

    print(f"\n✅ Encryption complete!")
    print(f"🔐 Encrypted file saved at: {enc_path}")
    print(f"🗝️  Keyfile saved at:       {keyfile_path}")
    print("\nKeep your password and keyfile safe — both are required to decrypt.")

# === Entry Point ===
if __name__ == '__main__':
    main()
