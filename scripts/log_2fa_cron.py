#!/usr/bin/env python3
"""
Cron script to log 2FA codes every minute.
"""

import os
import sys
from datetime import datetime, timezone

import base64
import pyotp

SEED_FILE = "/data/seed.txt"


def read_seed():
    """
    1. Read hex seed from persistent storage.
    - File path: /data/seed.txt
    - Strip whitespace and newlines.
    """
    if not os.path.exists(SEED_FILE):
        print(f"ERROR: Seed file not found at {SEED_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(SEED_FILE, "r", encoding="utf-8") as f:
        hex_seed = f.read().strip()

    if not hex_seed:
        print("ERROR: Seed file is empty", file=sys.stderr)
        sys.exit(1)

    return hex_seed


def generate_totp_code(hex_seed: str) -> str:
    """
    2. Generate current TOTP code from hex seed.
    - Convert hex -> bytes -> base32
    - Use same TOTP parameters as your main app
    """
    try:
        key_bytes = bytes.fromhex(hex_seed)
    except ValueError:
        print("ERROR: Seed is not valid hex", file=sys.stderr)
        sys.exit(1)

    base32_secret = base64.b32encode(key_bytes).decode("utf-8")

    totp = pyotp.TOTP(base32_secret)
    code = totp.now()
    return code


def get_timestamp():
    """
    3. Get current UTC timestamp.
    Format: YYYY-MM-DD HH:MM:SS
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main():
    seed = read_seed()
    code = generate_totp_code(seed)
    timestamp = get_timestamp()

    print(f"{timestamp} - 2FA Code: {code}")


if __name__ == "__main__":
    main()
