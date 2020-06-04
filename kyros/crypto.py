# pylint: disable=invalid-name
import Crypto.Cipher.AES
import Crypto.Hash
import Crypto.Protocol
import Crypto.Util.Padding


def hkdf_expand(key: bytes, length: int) -> bytes:
    """Expand a key to a length."""
    return Crypto.Protocol.KDF.HKDF(key, length, None, Crypto.Hash.SHA256)


def validate_secrets(secret: bytes, shared_secret_expanded: bytes) -> bool:
    """Validate secrets. Used during QR login process."""
    return Crypto.Hash.HMAC.new(shared_secret_expanded[32:64],
                                secret[:32] + secret[64:],
                                Crypto.Hash.SHA256).digest() == secret[32:64]


def hmac_sha256(mac: bytes, message: bytes) -> bytes:
    """Sign a message with a mac key."""
    return Crypto.Hash.HMAC.new(mac, message, Crypto.Hash.SHA256).digest()


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext using AES CBC."""
    plaintext = Crypto.Util.Padding.pad(plaintext,
                                        Crypto.Cipher.AES.block_size)
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC)
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using AES CBC."""
    iv = ciphertext[:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:])
    return Crypto.Util.Padding.unpad(plaintext, Crypto.Cipher.AES.block_size)
