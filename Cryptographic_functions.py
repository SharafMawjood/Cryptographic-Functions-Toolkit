import rsa
import os
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def generate_asymmetric_keys(name="client"):
    public_key, private_key = rsa.newkeys(512)
    with open(f"Keys\\public_key_{name}.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open(f"Keys\\private_key_{name}.pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))


def get_public_key(name="client"):
    with open(f"Keys\\public_key_{name}.pem", "rb") as f:
        return rsa.PublicKey.load_pkcs1(f.read())


def get_private_key(name="client"):
    with open(f"Keys\\private_key_{name}.pem", "rb") as f:
        return rsa.PrivateKey.load_pkcs1(f.read())


def sign_message(message, encoding=False, enc_type="utf-8"):
    signature = rsa.sign(message, get_private_key(), "SHA-256")
    if encoding == True:
        signature = rsa.sign(message.encode(), get_private_key(), "SHA-256")
    return signature


def verify_signature(message, signature, public_key, encoding=False, enc_type="utf-8"):
    try:
        rsa.verify(message, signature, public_key)
        if encoding == True:
            rsa.verify(message.encode(), signature, public_key)
        print("Verification successful!")

    except rsa.VerificationError:
        print("Verification failed.")


def encrypt_key(message, key, encoding=False, enc_type="utf-8"):
    if encoding == True:
        message = message.encode()
    encrypted_message = rsa.encrypt(message, key)
    return encrypted_message


def decrypt_key(encrypted_message, key, encoding=False, enc_type="utf-8"):
    decrypted_message = rsa.decrypt(encrypted_message, key)
    if encoding == True:
        decrypted_message = decrypted_message.decode()
    return decrypted_message


def bytes_to_pub_key(data):
    return rsa.PublicKey.load_pkcs1(data)


def bytes_to_priv_key(data):
    return rsa.PrivateKey.load_pkcs1(data)


def key_to_bytes(key):
    return key.save_pkcs1()


def generate_symmetric_key(size=32):
    key = get_random_bytes(size)
    iv = os.urandom(16)
    with open("Keys\\key.key", "wb") as f:
        f.write(key)


def generate_advanced_symmetric_key(passkey, salt, size=32):
    key = PBKDF2(passkey, salt, dkLen=size, count=1000000)
    # iv = os.urandom(16)
    with open("Keys\\key.key", "wb") as f:
        f.write(key)


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + encrypted_message


def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)
    return decrypted_message


def get_symmetric_key():
    with open("Keys\\key.key", "rb") as f:
        return f.read()


if __name__ == "__main__":
    # generate_symmetric_key()
    # encrypted_message = encrypt_message(b"Hello, world!", get_symmetric_key())
    # print(decrypt_message(encrypted_message, get_symmetric_key()))

    key = get_public_key()
    print(type(key))
    print(type(key.save_pkcs1().decode()))
    print(type(key_to_bytes(key).decode()))

