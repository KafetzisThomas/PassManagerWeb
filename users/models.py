from django.contrib.auth.models import AbstractUser
from django.db import models
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
    enable_2fa = models.BooleanField(default=False, verbose_name="Enable 2FA")
    otp_secret = models.CharField(max_length=32)
    session_timeout = models.IntegerField(
        choices=[(key, value) for value, key in SESSION_TIMEOUT_CHOICES],
        default=900,  # 15 minutes
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = CustomUserManager()

    def __str__(self):
        return self.email
