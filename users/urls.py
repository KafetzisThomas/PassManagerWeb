from django.urls import path
from django.contrib.auth import views as auth_views
from .views import CustomLoginView, TwoFactorVerificationView, register, account, update_master_password, delete_account

app_name = "users"
urlpatterns = [
    path("login/", CustomLoginView.as_view(), name="login"),
    path("login/2fa_verification/", TwoFactorVerificationView.as_view(), name="2fa_verification"),
    path("account/", account, name="account"),
    path("account/update_master_password/", update_master_password, name="update_master_password"),
    path("register/", register, name="register"),
    path("account/delete_account/", delete_account, name="delete_account"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
