import os
import json
import base64
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def vault_filename(username: str) -> str:
    return f"vault_{username}.json"


def load_vault(username: str, master_password: bytes):
    filename = vault_filename(username)
    if not os.path.exists(filename):
        print(
            f"❌ Vault for user '{username}' does not exist. Please create a new one first."
        )
        return None, None

    with open(filename, "r") as file:
        data = json.load(file)

    salt = base64.b64decode(data["salt"])
    vault_encrypted = data["vault_encrypted"].encode()
    key = derive_key(master_password, salt)

    try:
        f = Fernet(key)
        decrypted = f.decrypt(vault_encrypted)
        vault = json.loads(decrypted.decode())
        return vault, salt
    except InvalidToken:
        print("❌ Incorrect master key or corrupted vault.")
        return None, None


def save_vault(username: str, vault: dict, master_password: bytes, salt: bytes):
    filename = vault_filename(username)
    key = derive_key(master_password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(vault).encode())

    with open(filename, "w") as file:
        json.dump(
            {
                "salt": base64.b64encode(salt).decode(),
                "vault_encrypted": encrypted.decode(),
            },
            file,
            indent=4,
        )


def create_vault(username: str, master_password: bytes):
    salt = os.urandom(16)
    vault = {}
    save_vault(username, vault, master_password, salt)
    print(f"✅ Vault created successfully for user '{username}'.")
    return vault, salt


def add_entry(vault: dict):
    site = input("🌐 Site: ").strip()
    username = input("👤 Username: ").strip()
    password = getpass("🔑 Password: ").strip()
    vault[site] = {"username": username, "password": password}
    print(f"✅ Entry for {site} saved successfully.")


def list_entries(vault: dict):
    if not vault:
        print("📭 No credentials saved.")
        return

    for site, data in vault.items():
        print(f"\n🌐 Site: {site}")
        print(f"👤 Username: {data['username']}")
        print(f"🔑 Password: {data['password']}")


def show_main_menu():
    print("\n===== Welcome =====")
    print("1. Enter master key")
    print("2. Create new master key")
    print("3. Exit")
    print("===================")


def show_password_menu():
    print("\n===== Password Manager =====")
    print("1. Add new password")
    print("2. List all passwords")
    print("3. Logout")
    print("============================")


def main():
    vault = None
    salt = None
    master_password = None
    username = None

    while True:
        show_main_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = input("Enter your username: ").strip()
            master_password = getpass("Enter your master key: ").encode()
            vault, salt = load_vault(username, master_password)
            if vault is not None:
                print(f"✅ Vault unlocked successfully for user '{username}'!")
                break
            else:
                print("Failed to unlock vault. Try again or create a new master key.")
        elif choice == "2":
            username = input("Choose a new username: ").strip()
            while True:
                master_password = getpass("Create a new master key: ").encode()
                confirm_password = getpass("Confirm new master key: ").encode()
                if master_password != confirm_password:
                    print("❌ Passwords do not match. Try again.")
                elif len(master_password) == 0:
                    print("❌ Password cannot be empty. Try again.")
                else:
                    break
            vault, salt = create_vault(username, master_password)
            break
        elif choice == "3":
            print("👋 Goodbye!")
            return
        else:
            print("❌ Invalid option. Please choose 1, 2 or 3.")

    while True:
        show_password_menu()
        option = input("Choose an option: ").strip()

        if option == "1":
            add_entry(vault)
            save_vault(username, vault, master_password, salt)
        elif option == "2":
            list_entries(vault)
        elif option == "3":
            print("👋 Logging out...")
            break
        else:
            print("❌ Invalid option. Please try again.")


if __name__ == "__main__":
    main()
