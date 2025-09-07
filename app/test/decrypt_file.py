#!/usr/bin/env python3
"""
decrypt_file.py
- Decrypts an encrypted daily-log blob created by your app.
- Format: b'v1' + salt(16) + SecretBox(nonce + ciphertext + mac)
Usage:
  python decrypt_file.py                 # decrypt newest *.json.enc in CWD
  python decrypt_file.py path/to/file.json.enc
"""

from __future__ import annotations
import argparse
import json
from getpass import getpass
from pathlib import Path

from nacl import secret
from nacl.pwhash import argon2id

def decrypt_blob(blob: bytes, passphrase: str) -> dict:
    if len(blob) < 2 + argon2id.SALTBYTES + secret.SecretBox.NONCE_SIZE + 1:
        raise ValueError("Blob too short or corrupted.")
    if blob[:2] != b"v1":
        raise ValueError("Unknown blob version (expected 'v1').")
    salt = blob[2:2 + argon2id.SALTBYTES]
    ct   = blob[2 + argon2id.SALTBYTES:]

    key = argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )
    box = secret.SecretBox(key)
    pt = box.decrypt(ct)  # raises if wrong passphrase or tampered
    return json.loads(pt.decode("utf-8"))

def pick_newest_enc_file() -> Path | None:
    files = sorted(Path(".").glob("*.json.enc"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

def main():
    ap = argparse.ArgumentParser(description="Decrypt a daily-log .json.enc file")
    ap.add_argument("path", nargs="?", help="Path to .json.enc (defaults to newest in CWD)")
    args = ap.parse_args()

    file_path = Path(args.path) if args.path else pick_newest_enc_file()
    if not file_path or not file_path.exists():
        print("No file provided/found. Place a *.json.enc in this directory or pass a path.")
        return

    pw = getpass("Passphrase: ")
    try:
        obj = decrypt_blob(file_path.read_bytes(), pw)
    except Exception as e:
        print(f"Failed to decrypt {file_path}: {e}")
        return

    # Print nicely; supports single entry or {"entries":[...]}
    if isinstance(obj, dict) and "entries" in obj and isinstance(obj["entries"], list):
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(obj, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
