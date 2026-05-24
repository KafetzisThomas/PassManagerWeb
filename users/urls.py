from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = "users"
urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.CustomLoginView.as_view(template_name="users/login.html"), name="login"),
    path("login/2fa_verification/", views.two_factor_verification, name="2fa_verification"),
    path("account/", views.account, name="account"),
    path("account/update_master_password/", views.update_master_password, name="update_master_password"),
    path("account/delete_account/", views.delete_account, name="delete_account"),
    path("logout/", auth_views.LogoutView.as_view(next_page="users:login"), name="logout"),
]
