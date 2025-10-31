import os
import getpass
import secrets
from pathlib import Path
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

# === File Encryption Logic ===
def encrypt_file_gui():
    ensure_dirs()

    print("\n📁 Enter path to the file you want to encrypt:")
    infile = input("> ").strip().strip('"')

    in_path = Path(infile).expanduser()
    if not in_path.exists():
        print("❌ File not found:", in_path)
        return

    print("\n🔑 Enter encryption password (leave blank to be prompted):")
    password_input = input("> ").strip()
    password = password_input.encode() if password_input else getpass.getpass("Password: ").encode()

    file_key = secrets.token_bytes(32)
    enc_path = Path("encrypted_files") / (in_path.name + ".enc")
    keyfile_path = Path("keyfiles") / (in_path.name + ".key.json")

    print("\n⏳ Encrypting, please wait...")
    metadata = {"original_filename": in_path.name}

    encrypt_file_with_key(in_path, enc_path, file_key)
    create_keyfile(file_key, password, keyfile_path, metadata)

    print("\n✅ Encryption complete!")
    print(f"🔐 Encrypted file saved at: {enc_path}")
    print(f"🗝️  Keyfile saved at:       {keyfile_path}")
    print("\n⚠️  Keep your password and keyfile safe — both are required to decrypt.\n")

# === Main Menu ===
def main_menu():
    print(ASCII_ART)

    while True:
        print("=== SECRYPT — File Encryption Utility ===")
        print("[1] Encrypt a file")
        print("[2] Open encrypted_files folder")
        print("[3] Open keyfiles folder")
        print("[4] Exit")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            encrypt_file_gui()
        elif choice == "2":
            os.startfile("encrypted_files") if os.name == "nt" else os.system("open encrypted_files")
        elif choice == "3":
            os.startfile("keyfiles") if os.name == "nt" else os.system("open keyfiles")
        elif choice == "4":
            print("\n👋 Exiting SECRYPT. Stay safe!\n")
            break
        else:
            print("❌ Invalid choice. Please try again.\n")

# === Entry Point ===
if __name__ == "__main__":
    main_menu()
