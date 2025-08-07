from getpass import getpass
import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000
    )
    key = kdf.derive(password)
    return base64.urlsafe_b64encode(key)


if __name__ == "__main__":
    if os.path.exists("vault.json"):
        print("Vault already exists. Remove 'vault.json' if you want to restart.")
        exit(1)
    master_password = getpass("Insert your master password: ").encode()
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    vault = {}
    vault_bytes = json.dumps(vault).encode()
    f = Fernet(key)
    vault_encrypted = f.encrypt(vault_bytes)
    with open("vault.json", "w") as file:
        json.dump(
            {
                "salt": base64.b64encode(salt).decode(),
                "vault_encrypted": vault_encrypted.decode(),
            },
            file,
            indent=4,
        )
    print("✅ Vault initialized and saved to vault.json")
