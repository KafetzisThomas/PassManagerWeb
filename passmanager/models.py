import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.db import models


def derive_key_from_master_password(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key using PBKDF2HMAC.
    Based on user's master password & encryption salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


class Item(models.Model):
    name = models.CharField(max_length=50)
    username = models.TextField(blank=True)
    password = models.TextField(blank=True)
    url = models.URLField(max_length=50, blank=True)
    notes = models.TextField(max_length=1500, blank=True)
    group = models.CharField(max_length=50, default="General")
    date_added = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="items")

    @staticmethod
    def encrypt_field(key: bytes, value: str) -> str:
        """
        Encrypt value using AES GCM with a 256-bit key.
        """
        key_bytes = base64.urlsafe_b64decode(key)
        nonce = os.urandom(12)  # 12-bytes nonce for GCM
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(value.encode()) + encryptor.finalize()
        tag = encryptor.tag  # 16 bytes
        combined = nonce + ciphertext + tag
        return base64.urlsafe_b64encode(combined).decode()

    @staticmethod
    def decrypt_field(key: bytes, value: str) -> str:
        """
        Decrypt AES GCM encrypted data using the given key.
        """
        key_bytes = base64.urlsafe_b64decode(key)
        combined = base64.urlsafe_b64decode(value.encode())
        nonce = combined[:12]
        ciphertext = combined[12:-16]
        tag = combined[-16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode()

    def get_key(self) -> bytes:
        """
        Derive the encryption key using owner's master password,
        and their encryption salt.
        """
        salt = base64.urlsafe_b64decode(self.owner.encryption_salt)
        return derive_key_from_master_password(self.owner.password, salt)

    def encrypt_sensitive_fields(self) -> None:
        """
        Manually encrypt sensitive fields.
        """
        key = self.get_key()
        self.username = self.encrypt_field(key, self.username)
        self.password = self.encrypt_field(key, self.password)
        self.notes = self.encrypt_field(key, self.notes)

        key = None  # Zero out the content of the key in memory
        del key  # Securely forget the encryption key

    def decrypt_sensitive_fields(self) -> None:
        """
        Decrypt sensitive fields for display.
        """
        key = self.get_key()
        self.username = self.decrypt_field(key, self.username)
        self.password = self.decrypt_field(key, self.password)
        self.notes = self.decrypt_field(key, self.notes)

        key = None  # Zero out the content of the key in memory
        del key  # Securely forget the encryption key

    def save(self, *args, **kwargs):
        """
        Title-case name and group before saving.
        """
        self.name = self.name.title()
        if self.group:
            self.group = self.group.title()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name
