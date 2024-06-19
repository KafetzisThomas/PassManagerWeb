from cryptography.fernet import Fernet


def encrypt(message, key):
    return Fernet(key).encrypt(message)


def decrypt(token, key):
    return Fernet(key).decrypt(token)
