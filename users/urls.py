"""Defines URL patterns for users"""

from django.urls import path
from django.contrib.auth import views as auth_views
from .views import CustomLoginView
from . import views

app_name = "users"
urlpatterns = [
    # Login page
    path("login/", CustomLoginView.as_view(), name="login"),
    # 2FA verification page
    path(
        "login/2fa_verification/",
        views.TwoFactorVerificationView.as_view(),
        name="2fa_verification",
    ),
    # Account page
    path("account/", views.account, name="account"),
    # Update master password page
    path(
        "account/update_master_password/",
        views.update_master_password,
        name="update_master_password",
    ),
    # Registration page
    path("register/", views.register, name="register"),
    # Delete account page
    path("account/delete_account/", views.delete_account, name="delete_account"),
    # Logout page
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
