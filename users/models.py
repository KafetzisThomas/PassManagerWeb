import os
import base64
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext as _
from .managers import CustomUserManager

SESSION_TIMEOUT_CHOICES = (
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("15 minutes", 900),
    ("30 minutes", 1_800),
    ("1 hour", 3_600),
    ("3 hours", 10_800),
)


class CustomUser(AbstractUser):
    email = models.EmailField(_("email address"), unique=True)
    encryption_salt = models.CharField(max_length=44, blank=True, null=True)
    enable_2fa = models.BooleanField(default=False, verbose_name="Enable 2FA")
    otp_secret = models.CharField(max_length=32)
    allow_account_update_notifications = models.BooleanField(
        default=True, verbose_name="Allow Account Update Notifications"
    )
    allow_master_password_update_notifications = models.BooleanField(
        default=True, verbose_name="Allow Master Password Update Notifications"
    )
    session_timeout = models.IntegerField(
        choices=[(key, value) for value, key in SESSION_TIMEOUT_CHOICES],
        default=900,  # 15 minutes
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = CustomUserManager()

    def save(self, *args, **kwargs):
        if not self.encryption_salt:
            self.encryption_salt = base64.urlsafe_b64encode(os.urandom(32)).decode()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
