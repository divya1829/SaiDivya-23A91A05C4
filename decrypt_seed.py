import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def load_private_key():
    """Load student private key from PEM file."""
    with open("student_private.pem", "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None)


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256).

    Returns:
        64-character hex string.
    """

    # 1. Base64 decode
    try:
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except Exception:
        raise ValueError("Invalid base64 encrypted seed")

    # 2. RSA OAEP Decrypt (SHA-256, MGF1-SHA256, label=None)
    try:
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

    # 3. Convert bytes → UTF-8 string
    try:
        hex_seed = decrypted_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Decrypted seed is not valid UTF-8")

    # 4. Validate hex seed format
    if len(hex_seed) != 64:
        raise ValueError("Seed must be 64 characters long")

    allowed = "0123456789abcdef"
    if any(ch not in allowed for ch in hex_seed):
        raise ValueError("Seed contains invalid characters (must be hex)")

    return hex_seed


# Manual test helper
if __name__ == "__main__":
    private_key = load_private_key()

    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed = f.read().strip()

    seed = decrypt_seed(encrypted_seed, private_key)
    print("Decrypted seed:", seed)
