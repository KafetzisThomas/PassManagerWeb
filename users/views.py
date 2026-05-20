import pyotp
from django.shortcuts import render, redirect
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.views.generic.edit import FormView
from django.contrib import messages
from .models import CustomUser
from passmanager.models import Item
from .forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    TwoFactorVerificationForm,
    CustomUserChangeForm,
    MasterPasswordChangeForm,
)

def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account successfully created!")
            return redirect("users:login")
    else:
        form = CustomUserCreationForm()
    return render(request, "users/register.html", {"form": form})

@login_required
def account(request):
    if request.method == "POST":
        form = CustomUserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            user.enable_2fa = form.cleaned_data.get("enable_2fa", False)

            if user.enable_2fa:
                user.otp_secret = pyotp.random_base32()
                messages.success(request, "2FA enabled! Check your email for the OTP key.")
            else:
                user.otp_secret = ""

            user.save()
            update_session_auth_hash(request, request.user)  # keep user logged in
            messages.success(request, "Your account credentials were successfully updated!")
            return redirect("passmanager:vault")
        else:
            messages.error(request, "There was an error updating your account.")

    else:
        form = CustomUserChangeForm(instance=request.user)

    return render(request, "users/account.html", {"form": form})

@login_required
def update_master_password(request):
    if request.method == "POST":
        form = MasterPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            old_password = form.cleaned_data["old_password"]
            new_password = form.cleaned_data["new_password1"]

            if not request.user.check_password(old_password):
                messages.error(request, "Old master password is incorrect.")
                return redirect("users:update_master_password")

            user = request.user
            items = Item.objects.filter(owner=user)

            if items.exists():
                old_key = items.first().get_key()
                for item in items:
                    item.username = item.decrypt_field(old_key, item.username)
                    item.password = item.decrypt_field(old_key, item.password)
                    item.notes = item.decrypt_field(old_key, item.notes)

            user.set_password(new_password)
            user.save()

            if items.exists():
                for item in items:
                    new_key = item.get_key()
                    item.username = item.encrypt_field(new_key, item.username)
                    item.password = item.encrypt_field(new_key, item.password)
                    item.notes = item.encrypt_field(new_key, item.notes)
                    item.save()

            messages.success(request, "Your master password was successfully updated!")
            return redirect("passmanager:vault")
    else:
        form = MasterPasswordChangeForm(user=request.user)

    return render(request, "users/update_master_password.html", {"form": form})

@login_required
def delete_account(request):
    user = request.user
    user.delete()
    return redirect("users:register")


class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm
    def form_valid(self, form):
        user = form.get_user()
        if user.otp_secret:
            self.request.session["user_id"] = user.id
            return redirect("users:2fa_verification")
        return super().form_valid(form)


class TwoFactorVerificationView(FormView):
    template_name = "users/2fa_verification.html"
    form_class = TwoFactorVerificationForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        user_id = self.request.session.get("user_id")
        kwargs["user"] = CustomUser.objects.get(id=user_id)
        return kwargs

    def form_valid(self, form):
        user = form.user
        backend_path = "django.contrib.auth.backends.ModelBackend"
        login(self.request, user, backend=backend_path)

        self.request.session.pop("user_id", None)
        return redirect("passmanager:vault")
