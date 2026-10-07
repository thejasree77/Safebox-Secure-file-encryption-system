import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# OAEP padding settings used for wrapping/unwrapping keys with RSA
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

# ---------- RSA key handling ----------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def load_public_key(pem):
    return serialization.load_pem_public_key(pem)

def private_key_to_encrypted_pem(private_key, password):
    """The private key is stored encrypted with the user's password."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )

def load_private_key(pem, password):
    return serialization.load_pem_private_key(pem, password.encode())

# ---------- Wrap / unwrap a key with RSA ----------
def wrap_key(key_bytes, public_key):
    return public_key.encrypt(key_bytes, OAEP)

def unwrap_key(wrapped, private_key):
    return private_key.decrypt(wrapped, OAEP)

# ---------- File encryption with AES-256-GCM ----------
def encrypt_bytes(data):
    """Returns (aes_key, blob). blob = 12-byte nonce + ciphertext + tag."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)                       # new random nonce for every file
    return aes_key, nonce + AESGCM(aes_key).encrypt(nonce, data, None)

def decrypt_bytes(aes_key, blob):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)   # InvalidTag if tampered

# ---------- Smart key management: key / password -> 256-bit key ----------
def derive_kek(secret, salt):
    """Password or generated key -> Scrypt -> 256-bit key."""
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(secret.encode())

def lock_key(aes_key, secret, salt):
    """Encrypt the file's AES key with a key derived from the secret."""
    nonce = os.urandom(12)
    return nonce + AESGCM(derive_kek(secret, salt)).encrypt(nonce, aes_key, None)

def unlock_key(locked, secret, salt):
    """Raises InvalidTag when the secret is wrong."""
    return AESGCM(derive_kek(secret, salt)).decrypt(locked[:12], locked[12:], None)