from django.urls import path
from django.contrib.auth import views as auth_views
from .views import CustomLoginView, TwoFactorVerificationView, RegisterView, AccountView, UpdateMasterPasswordView, delete_account

app_name = "users"
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("login/2fa_verification/", TwoFactorVerificationView.as_view(), name="2fa_verification"),
    path("account/", AccountView.as_view(), name="account"),
    path("account/update_master_password/", UpdateMasterPasswordView.as_view(), name="update_master_password"),
    path("account/delete_account/", delete_account, name="delete_account"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
