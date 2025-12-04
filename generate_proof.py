import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---- STEP 1: Put your commit hash here ----
commit_hash = "395a07ed0141e2639535a5b5ae2ff3e54ef9e10e"
message_bytes = commit_hash.encode("utf-8")


# ---- STEP 2: Load your student private key ----
priv_key_data = Path("student_private.pem").read_bytes()
private_key = serialization.load_pem_private_key(
    priv_key_data, password=None
)


# ---- STEP 3: Sign hash (RSA-PSS-SHA256) ----
signature = private_key.sign(
    message_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)


# ---- STEP 4: Load instructor public key ----
instr_pub_data = Path("instructor_public.pem").read_bytes()
instr_public_key = serialization.load_pem_public_key(instr_pub_data)


# ---- STEP 5: Encrypt signature using RSA-OAEP-SHA256 ----
cipher = instr_public_key.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)


# ---- STEP 6: Base64 encode encrypted signature ----
encrypted_b64 = base64.b64encode(cipher).decode("utf-8")


# ---- Print results ----
print("\n===== Your Final Commit Proof =====")
print("Commit Hash:")
print(commit_hash)
print("\nEncrypted Signature (Base64):")
print(encrypted_b64)
print("====================================\n")
