
import os, json, base64, re, time
import pyperclip
from getpass import getpass
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import choice
import string

VAULT_FILE = "vault.json"
LOG_FILE = "audit.log"

def log_action(action):
    with open(LOG_FILE, "a") as log:
        log.write(f"[{datetime.now()}] {action}\n")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_data(data: dict, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_data(enc_dict: dict, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc_dict["nonce"])
    ct = base64.b64decode(enc_dict["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode())

def initialize_vault():
    if not os.path.exists(VAULT_FILE):
        salt = os.urandom(16)
        with open(VAULT_FILE, "w") as f:
            json.dump({"salt": base64.b64encode(salt).decode(), "vault": {}}, f)

def load_vault():
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault(data: dict):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f)

def check_password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
    return score

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(choice(characters) for _ in range(length))

def clear_clipboard_after(seconds):
    time.sleep(seconds)
    pyperclip.copy('')

def clipboard_with_timeout(content, timeout=10):
    pyperclip.copy(content)
    print(f"📋 Password copied to clipboard. It will be cleared in {timeout} seconds.")
    from threading import Thread
    Thread(target=clear_clipboard_after, args=(timeout,), daemon=True).start()

def change_master_password(current_key, current_salt, vault):
    print("\n🔐 Change Master Password")
    confirm = getpass("Re-enter current master password: ")
    try:
        test_key = derive_key(confirm, current_salt)
        _ = encrypt_data(vault, test_key)
    except Exception:
        print("❌ Incorrect master password.")
        return current_key, current_salt

    new_password = getpass("Enter NEW master password: ")
    confirm_password = getpass("Confirm NEW master password: ")

    if new_password != confirm_password:
        print("❌ Passwords do not match.")
        return current_key, current_salt

    new_salt = os.urandom(16)
    new_key = derive_key(new_password, new_salt)
    encrypted_data = encrypt_data(vault, new_key)
    save_vault({"salt": base64.b64encode(new_salt).decode(), "vault": encrypted_data})
    log_action("Changed master password.")
    print("✅ Master password changed successfully.")
    return new_key, new_salt

def main():
    print("\n🔐 Welcome to Secure Password Manager\n")
    initialize_vault()
    vault_data = load_vault()
    salt = base64.b64decode(vault_data["salt"])
    master_pwd = getpass("Enter your master password: ")

    try:
        key = derive_key(master_pwd, salt)
        if vault_data.get("vault"):
            vault = decrypt_data(vault_data["vault"], key)
        else:
            vault = {}
    except Exception:
        print("❌ Invalid password or corrupted vault.")
        return

    while True:
        print("\nMenu:")
        print("[1] Add password")
        print("[2] Retrieve password")
        print("[3] Delete password")
        print("[4] Search for a service")
        print("[5] Generate a strong password")
        print("[6] Exit")
        print("[7] Change master password")
        print("[8] View audit log")
        choice = input("Choose an option (1-8): ")

        if choice == "1":
            service = input("Service name: ")
            username = input("Username: ")
            view = input("Do you want to view the password before saving? (y/n): ").lower()
            password = input("Password: ") if view == "y" else getpass("Password: ")
            strength = check_password_strength(password)
            if strength < 3:
                print("⚠️ Weak password! Consider using a stronger one.")
            vault[service] = {"username": username, "password": password}
            log_action(f"Added entry for service: {service}")
            print("✅ Password saved.")

        elif choice == "2":
            service = input("Service name to retrieve: ")
            if service in vault:
                print(f"Username: {vault[service]['username']}")
                clipboard_with_timeout(vault[service]['password'])
                log_action(f"Retrieved password for service: {service}")
            else:
                print("⚠️ Service not found.")

        elif choice == "3":
            service = input("Service name to delete: ")
            if service in vault:
                del vault[service]
                log_action(f"Deleted entry for service: {service}")
                print("✅ Entry deleted.")
            else:
                print("⚠️ Service not found.")

        elif choice == "4":
            term = input("Enter search keyword: ").lower()
            results = [s for s in vault if term in s.lower()]
            if results:
                print("🔍 Matching Services:")
                for s in results:
                    print(f"- {s}")
            else:
                print("❌ No matches found.")

        elif choice == "5":
            length = input("Password length (default 12): ")
            try:
                length = int(length)
            except:
                length = 12
            generated = generate_strong_password(length)
            print(f"Generated Password: {generated}")
            clipboard_with_timeout(generated)
            log_action(f"Generated password of length {length}")

        elif choice == "6":
            encrypted_data = encrypt_data(vault, key)
            save_vault({
                "salt": base64.b64encode(salt).decode(),
                "vault": encrypted_data
            })
            log_action("Exited and saved vault securely.")
            print("🔒 Vault encrypted and saved. Goodbye!")
            break

        elif choice == "7":
            key, salt = change_master_password(key, salt, vault)

        elif choice == "8":
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as log:
                    print("\n📜 Audit Log:\n" + log.read())
            else:
                print("📄 No audit log found yet.")

        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()
