import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models


def derive_key_from_master_password(master_password, salt):
    """
    Derive an encryption key from the user's master password,
    and encryption salt.
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
    username = models.CharField(max_length=500)
    password = models.CharField(max_length=500)
    url = models.URLField(max_length=50)
    notes = models.TextField(max_length=1500)
    date_added = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def encrypt_field(self, key, value):
        """
        Encrypt field value using the given key.
        """
        return Fernet(key).encrypt(value.encode()).decode()

    def decrypt_field(self, key, value):
        """
        Decrypt field value using the given key.
        """
        return Fernet(key).decrypt(value.encode()).decode()

    def get_key(self):
        """
        Derive the encryption key using owner's master password,
        and their encryption salt.
        """
        salt = self.owner.encryption_salt.encode()
        return derive_key_from_master_password(self.owner.password, salt)

    def save(self, *args, **kwargs):
        """
        Encrypt sensitive fields before saving.
        """
        key = self.get_key()
        self.username = self.encrypt_field(key, self.username)
        self.password = self.encrypt_field(key, self.password)
        self.notes = self.encrypt_field(key, self.notes)
        print(key)
        del key  # Securely forget the encryption key
        super().save(*args, **kwargs)

    def decrypt_sensitive_fields(self):
        """
        Decrypt sensitive fields for display.
        """
        key = self.get_key()
        self.username = self.decrypt_field(key, self.username)
        self.password = self.decrypt_field(key, self.password)
        self.notes = self.decrypt_field(key, self.notes)
        del key  # Securely forget the encryption key

    def __str__(self):
        return self.name
