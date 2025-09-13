import os
import base64
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext as _

SESSION_TIMEOUT_CHOICES = (
    ("5 minutes", 300),
    ("10 minutes", 600),
    ("15 minutes", 900),
    ("30 minutes", 1_800),
    ("1 hour", 3_600),
    ("3 hours", 10_800),
)


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifier for authentication instead of usernames.
    """
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_("Users must have an email address"))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        if not extra_fields["is_staff"] or not extra_fields["is_superuser"]:
            raise ValueError(_("Superuser must have is_staff=True and is_superuser=True."))
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    email = models.EmailField(_("email address"), unique=True)
    username = models.CharField(max_length=150)
    encryption_salt = models.CharField(max_length=44, blank=True, null=True)
    enable_2fa = models.BooleanField(default=False, verbose_name="Enable 2FA")
    otp_secret = models.CharField(max_length=32, blank=True, null=True)
    allow_account_update_notifications = models.BooleanField(default=True)
    allow_master_password_update_notifications = models.BooleanField(default=True)
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

    def __str__(self) -> str:
        return self.email
