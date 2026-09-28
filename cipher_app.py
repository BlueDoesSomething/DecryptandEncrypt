"""
Cipher App - Midterm Project InfoSec
Ciphers: Caesar, Vigenere, AES-256-GCM (PBKDF2)
Run: python cipher_app.py
For AES: pip install cryptography
Ionic port: see ionic-app/src/app/home/
"""

import os
import base64
import getpass

# ---------- CAESAR ----------
def caesar_encrypt(plaintext: str, shift: int) -> str:
    shift %= 26
    out = []
    for ch in plaintext:
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)

# ---------- VIGENERE ----------
def _clean_key(keyword: str) -> str:
    key = ''.join(c for c in keyword if c.isalpha()).upper()
    if not key:
        raise ValueError("Keyword must contain at least one letter.")
    return key

def vigenere_encrypt(plaintext: str, keyword: str) -> str:
    key = _clean_key(keyword)
    out, ki = [], 0
    for ch in plaintext:
        s = ord(key[ki % len(key)]) - 65
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - 65 + s) % 26 + 65)); ki += 1
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - 97 + s) % 26 + 97)); ki += 1
        else:
            out.append(ch)
    return ''.join(out)

def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    key = _clean_key(keyword)
    out, ki = [], 0
    for ch in ciphertext:
        s = ord(key[ki % len(key)]) - 65
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - 65 - s) % 26 + 65)); ki += 1
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - 97 - s) % 26 + 97)); ki += 1
        else:
            out.append(ch)
    return ''.join(out)

# ---------- AES-256-GCM (compatible with Ionic WebCrypto) ----------
# Format: b64(salt):b64(iv):b64(ciphertext+tag)
ITERATIONS = 100_000

def _get_aes_libs():
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return PBKDF2HMAC, hashes, AESGCM
    except ImportError:
        return None, None, None

def aes_encrypt(plaintext: str, password: str) -> str:
    PBKDF2HMAC, hashes, AESGCM = _get_aes_libs()
    if PBKDF2HMAC is None:
        raise RuntimeError("Missing 'cryptography' lib. Run: pip install cryptography")
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return f"{b(salt)}:{b(iv)}:{b(ct)}"

def aes_decrypt(token: str, password: str) -> str:
    PBKDF2HMAC, hashes, AESGCM = _get_aes_libs()
    if PBKDF2HMAC is None:
        raise RuntimeError("Missing 'cryptography' lib. Run: pip install cryptography")
    try:
        b_salt, b_iv, b_ct = token.strip().split(":")
        salt, iv, ct = base64.b64decode(b_salt), base64.b64decode(b_iv), base64.b64decode(b_ct)
    except Exception:
        raise ValueError("Invalid AES format. Expected salt:iv:ciphertext (base64).")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.encode())
    try:
        pt = AESGCM(key).decrypt(iv, ct, None)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")
    return pt.decode()

# ---------- CLI ----------
def _input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        raise SystemExit

def _int_input(prompt: str, default: int = 3) -> int:
    raw = _input(prompt).strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"Invalid number, using {default}.")
        return default

def main():
    print("=" * 50)
    print("  ENCRYPT / DECRYPT APP  (Caesar | Vigenere | AES)")
    print("=" * 50)
    while True:
        print("\nChoose cipher:")
        print("  [1] Caesar")
        print("  [2] Vigenere")
        print("  [3] AES-256-GCM")
        print("  [0] Exit")
        choice = _input(">> ").strip()
        if choice == "0":
            print("Goodbye!"); break
        if choice not in ("1", "2", "3"):
            print("Invalid choice."); continue

        print("\nMode: [E]ncrypt  [D]ecrypt  [B]ack")
        mode = _input(">> ").strip().upper()
        if mode == "B":
            continue
        if mode not in ("E", "D"):
            print("Invalid mode."); continue
        is_enc = mode == "E"

        try:
            if choice == "1":
                shift = _int_input("Shift (0-25, default 3): ", 3)
                text = _input("Enter ciphertext/plaintext: " if not is_enc else "Enter plaintext: ")
                # For decrypt the prompt above is swapped; ask generically:
                result = caesar_encrypt(text, shift) if is_enc else caesar_decrypt(text, shift)
                print(f"\n{'Encrypted' if is_enc else 'Decrypted'}: {result}")

            elif choice == "2":
                kw = _input("Keyword: ").strip()
                text = _input("Enter plaintext: " if is_enc else "Enter ciphertext: ")
                result = vigenere_encrypt(text, kw) if is_enc else vigenere_decrypt(text, kw)
                print(f"\n{'Encrypted' if is_enc else 'Decrypted'}: {result}")

            else:  # AES
                pw = getpass.getpass("Password: ")
                text = _input("Enter plaintext: " if is_enc else "Enter ciphertext (salt:iv:data): ")
                result = aes_encrypt(text, pw) if is_enc else aes_decrypt(text, pw)
                print(f"\n{'Encrypted' if is_enc else 'Decrypted'}: {result}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
