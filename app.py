# app.py
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import base64
import os
from pathlib import Path
import time

# crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.backends import default_backend

# totp
import pyotp

DATA_SEED_PATH = Path("/data/seed.txt")    # assignment required path
PRIVATE_KEY_PATH = Path("student_private.pem")  # ensure this file is present in the repo

app = FastAPI(title="TOTP assignment API")


# ---------- Models ----------
class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# ---------- Helpers ----------
def load_private_key(path: Path, password: bytes | None = None) -> RSAPrivateKey:
    if not path.exists():
        raise FileNotFoundError(f"Private key not found at {path}")
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())


def decrypt_seed_base64(encrypted_seed_b64: str, private_key: RSAPrivateKey) -> str:
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64, validate=True)
    except Exception as e:
        raise ValueError("Invalid base64 encrypted_seed") from e

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("RSA decryption failed") from e

    try:
        s = plaintext.decode("utf-8").strip()
    except Exception as e:
        raise ValueError("Decrypted data not valid UTF-8") from e

    if len(s) != 64 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise ValueError("Decrypted seed not a 64-character hexadecimal string")

    return s.lower()


def write_seed_file(hex_seed: str, path: Path = DATA_SEED_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(hex_seed, encoding="utf-8")


def read_seed_file(path: Path = DATA_SEED_PATH) -> str:
    if not path.exists():
        raise FileNotFoundError("Seed not decrypted yet")
    s = path.read_text(encoding="utf-8").strip()
    if len(s) != 64:
        raise ValueError("Seed file malformed")
    return s


def hex_to_base32(hex_seed: str) -> str:
    b = bytes.fromhex(hex_seed)
    return base64.b32encode(b).decode().rstrip("=")


def generate_totp_and_remaining(hex_seed: str) -> tuple[str, int]:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    code = totp.now()
    period = 30
    now = int(time.time())
    elapsed = now % period
    remaining = period - elapsed
    return code, remaining


def verify_totp(hex_seed: str, code: str, window: int = 1) -> bool:
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    return totp.verify(code, valid_window=window)


# ---------- Endpoints ----------
@app.post("/decrypt-seed")
async def post_decrypt_seed(req: DecryptRequest):
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Private key missing on server"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to load private key"})

    try:
        hex_seed = decrypt_seed_base64(req.encrypted_seed, priv)
        write_seed_file(hex_seed)
        return {"status": "ok"}
    except ValueError as e:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed", "reason": str(e)})


@app.get("/generate-2fa")
async def get_generate_2fa():
    try:
        hex_seed = read_seed_file()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed file read error"})

    try:
        code, remaining = generate_totp_and_remaining(hex_seed)
        return {"code": code, "valid_for": remaining}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "TOTP generation failed"})


@app.post("/verify-2fa")
async def post_verify_2fa(req: VerifyRequest):
    if not req.code or req.code.strip() == "":
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    try:
        hex_seed = read_seed_file()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed file read error"})

    try:
        valid = verify_totp(hex_seed, req.code.strip(), window=1)
        return {"valid": bool(valid)}
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})


# ---------- Health Endpoint ----------
@app.get("/health")
async def health_check():
    """
    Shows last OTP generated by cron from /cron/last_code.txt
    """
    log_path = Path("/cron/last_code.txt")

    if not log_path.exists():
        return {
            "status": "not_ready",
            "message": "Cron has not generated any codes yet."
        }

    try:
        content = log_path.read_text(encoding="utf-8").strip()
        if not content:
            return {"status": "not_ready", "message": "Log is empty"}
        last_line = content.split("\n")[-1]
    except Exception as e:
        return {"status": "error", "message": str(e)}

    return {
        "status": "healthy",
        "last_code": last_line
    }
