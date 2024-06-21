from cryptography.fernet import Fernet
import string
import random


def encrypt(message, key):
    return Fernet(key).encrypt(message)


def decrypt(token, key):
    return Fernet(key).decrypt(token)


def generate_password(length, include_letters, include_digits, include_special_chars):
    characters = ""
    if include_letters:
        characters += string.ascii_letters
    if include_digits:
        characters += string.digits
    if include_special_chars:
        characters += string.punctuation
    return "".join(random.choice(characters) for _ in range(length))
