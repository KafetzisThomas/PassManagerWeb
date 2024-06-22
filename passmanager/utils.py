from cryptography.fernet import Fernet
import pwnedpasswords


def encrypt(message, key):
    return Fernet(key).encrypt(message)


def decrypt(token, key):
    return Fernet(key).decrypt(token)


def check_password(password):
    return pwnedpasswords.check(password, plain_text=True)
