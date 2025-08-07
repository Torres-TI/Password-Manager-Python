import os
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = kdf.derive(password)
    return base64.urlsafe_b64encode(key)


if not os.path.exists("vault.json"):
    print("File 'vault.json' not found. Have you initialized the vault?")
    exit(1)
master_password = getpass("Enter your master password: ").encode()
with open("vault.json", "r") as file:
    data = json.load(file)
salt = base64.b64decode(data["salt"])
vault_encrypted = data["vault_encrypted"].encode()
key = derive_key(master_password, salt)
try:
    f = Fernet(key)
    vault_decrypted = f.decrypt(vault_encrypted)
    vault = json.loads(vault_decrypted.decode())
    print("✅ Vault opened successfully!")
    print("Vault contents:", vault)
except InvalidToken:
    print("❌ Incorrect password or corrupted vault.")
