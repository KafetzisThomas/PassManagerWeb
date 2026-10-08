from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ("email", "username", "enable_2fa", "is_active", "is_superuser", "last_login")
    list_filter = ("is_superuser", "enable_2fa", "is_active")
    fieldsets = (
        (None, {"fields": ("username", "email", "password")}),
        ("Encryption", {"fields": ("encryption_salt", "enable_2fa", "otp_secret")}),
        ("Permissions", {"fields": ("is_active", "is_superuser")}),
        ("Session", {"fields": ("session_timeout",)}),
        ("Dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2", "enable_2fa"),
        }),
    )
    search_fields = ("email", "username")
    ordering = ("email",)
