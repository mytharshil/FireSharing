import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# ====================================================================
# Constants
# ====================================================================
AES_KEY_SIZE = 32        # AES-256
RSA_KEY_SIZE = 2048      # RSA-2048
SCRYPT_N = 2 ** 17       # CPU/memory cost (131072)
SCRYPT_R = 8             # Block size
SCRYPT_P = 1             # Parallelisation
SALT_SIZE = 32           # Salt for KDF
IV_SIZE = 16             # AES-GCM nonce
TAG_SIZE = 16            # AES-GCM tag

# ====================================================================
# AES-256-GCM Authenticated Encryption
# ====================================================================

def generate_aes_key() -> bytes:
    return get_random_bytes(AES_KEY_SIZE)


def aes_encrypt(data: bytes, key: bytes, aad: bytes = None) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def aes_decrypt(enc_data: bytes, key: bytes, aad: bytes = None) -> bytes:
    nonce = enc_data[:IV_SIZE]
    tag = enc_data[IV_SIZE:IV_SIZE + TAG_SIZE]
    ciphertext = enc_data[IV_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ====================================================================
# RSA-2048 Key Management
# ====================================================================

def generate_rsa_keypair():
    key = RSA.generate(RSA_KEY_SIZE)
    return key, key.publickey()


def rsa_encrypt(data: bytes, pub_key: RSA.RsaKey) -> bytes:
    from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data)


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes:
    from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(enc_data)


# ====================================================================
# Private Key Encryption at Rest (Password-Based)
# ====================================================================

def encrypt_private_key(priv_key: RSA.RsaKey, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    kdf_key = scrypt(password.encode(), salt, AES_KEY_SIZE, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    pem_data = priv_key.export_key('PEM')
    enc_data = aes_encrypt(pem_data, kdf_key)
    return salt + enc_data


def decrypt_private_key(enc_data: bytes, password: str) -> RSA.RsaKey:
    salt = enc_data[:SALT_SIZE]
    rest = enc_data[SALT_SIZE:]
    kdf_key = scrypt(password.encode(), salt, AES_KEY_SIZE, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    pem_data = aes_decrypt(rest, kdf_key)
    return RSA.import_key(pem_data)


def private_key_to_encrypted_pem(priv_key: RSA.RsaKey, password: str) -> str:
    return base64.b64encode(encrypt_private_key(priv_key, password)).decode()


def encrypted_pem_to_private_key(enc_pem: str, password: str) -> RSA.RsaKey:
    return decrypt_private_key(base64.b64decode(enc_pem), password)


# ====================================================================
# Digital Signatures (RSA + SHA-256)
# ====================================================================

def sign_data(data: bytes, priv_key: RSA.RsaKey) -> bytes:
    h = SHA256.new(data)
    return pkcs1_15.new(priv_key).sign(h)


def verify_signature(data: bytes, signature: bytes, pub_key: RSA.RsaKey) -> bool:
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ====================================================================
# File Integrity Hashing
# ====================================================================

def hash_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ====================================================================
# Serialisation Helpers
# ====================================================================

def key_to_pem(key) -> bytes:
    return key.export_key('PEM')


def pem_to_key(pem: bytes):
    return RSA.import_key(pem)
