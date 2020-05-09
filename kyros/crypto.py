import Crypto.Cipher.AES
import Crypto.Hash
import Crypto.Protocol


def hkdf_expand(key, length):
    return Crypto.Protocol.KDF.HKDF(key, length, None, Crypto.Hash.SHA256)


def validate_secrets(secret, shared_secret_expanded):
    breakpoint()
    return Crypto.Hash.HMAC.new(shared_secret_expanded[32:64],
                                secret[:32] + secret[64:],
                                Crypto.Hash.SHA256).digest() == secret[32:64]


def aes_pad(s):
    bs = Crypto.Cipher.AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)


def aes_unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def aes_decrypt(key, ciphertext):
    iv = ciphertext[:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:])
    return aes_unpad(plaintext)
