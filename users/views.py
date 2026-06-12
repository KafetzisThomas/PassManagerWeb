import pyotp
import qrcode
import base64
from io import BytesIO
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.contrib import messages
from .models import CustomUser
from vault.models import Item
from .forms import (
    RegistrationForm,
    LoginForm,
    EmailUpdateForm,
    UsernameUpdateForm,
    MasterPasswordChangeForm,
    TwoFactorToggleForm,
    TwoFactorVerificationForm,
    SessionTimeoutUpdateForm,
)
from .utils import send_discord_signup_alert

def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            messages.success(request, "Your account is pending approval. You'll be able to log in once approved.")
            send_discord_signup_alert(user)
            return redirect("users:login")
    else:
        form = RegistrationForm()
    return render(request, "users/register.html", {"form": form})

def two_factor_verification(request):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect("users:login")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        form = TwoFactorVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get("otp")
            if user.otp_secret and pyotp.TOTP(user.otp_secret).verify(otp):
                login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                request.session.pop("user_id", None)
                return redirect("vault:vault")
            else:
                form.add_error("otp", "Invalid OTP.")
    else:
        form = TwoFactorVerificationForm()

    return render(request, "users/2fa_verification.html", {"form": form})

@login_required
def account(request):
    user = request.user
    email_form = EmailUpdateForm(instance=user)
    username_form = UsernameUpdateForm(instance=user)
    session_form = SessionTimeoutUpdateForm(instance=user)
    tfa_form = TwoFactorToggleForm(instance=user)

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "update_email":
            email_form = EmailUpdateForm(request.POST, instance=user)
            if email_form.is_valid():
                email_form.save()
                messages.success(request, "Email updated successfully.")
                return redirect("users:account")

        elif action == "update_username":
            username_form = UsernameUpdateForm(request.POST, instance=user)
            if username_form.is_valid():
                username_form.save()
                messages.success(request, "Username updated successfully.")
                return redirect("users:account")

        elif action == "update_session":
            session_form = SessionTimeoutUpdateForm(request.POST, instance=user)
            if session_form.is_valid():
                session_form.save()
                messages.success(request, "Session timeout updated successfully.")
                return redirect("users:account")

        elif action == "toggle_2fa":
            tfa_form = TwoFactorToggleForm(request.POST, instance=user)
            if tfa_form.is_valid():
                user = tfa_form.save(commit=False)
                if user.enable_2fa:
                    user.enable_2fa = False
                    user.otp_secret = pyotp.random_base32()
                    user.save()

                    otp = pyotp.TOTP(user.otp_secret)
                    uri = otp.provisioning_uri(name=user.email, issuer_name="PassManagerWeb")

                    qr = qrcode.make(uri)
                    qr = qr.resize((150, 150))
                    buffer = BytesIO()
                    qr.save(buffer, format="PNG")
                    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

                    user.enable_2fa = True
                    display_form = TwoFactorToggleForm(instance=user)
                    user.enable_2fa = False

                    context = {
                        "email_form": email_form,
                        "username_form": username_form,
                        "session_form": session_form,
                        "show_2fa_modal": True,
                        "qr_code": qr_base64,
                        "otp_secret": user.otp_secret,
                        "tfa_form": display_form,
                    }
                    return render(request, "users/account.html", context)
                else:
                    user.enable_2fa = False
                    user.otp_secret = ""
                    user.save()
                    messages.success(request, "2FA disabled.")
                    return redirect("users:account")

        elif action == "confirm_2fa":
            otp = request.POST.get("otp")
            otp_secret = user.otp_secret

            if otp_secret and pyotp.TOTP(otp_secret).verify(otp):
                user.enable_2fa = True
                user.save()
                messages.success(request, "2FA enabled successfully!")
            else:
                user.otp_secret = ""
                user.save()
                messages.error(request, "Invalid OTP. 2FA setup failed.")
            return redirect("users:account")

        elif action == "cancel_2fa":
            user.enable_2fa = False
            user.otp_secret = ""
            user.save()
            return redirect("users:account")

    context = {
        "email_form": email_form,
        "username_form": username_form,
        "session_form": session_form,
        "tfa_form": tfa_form,
    }
    return render(request, "users/account.html", context)

@login_required
def update_master_password(request):
    user = request.user
    if request.method == "POST":
        form = MasterPasswordChangeForm(user, request.POST)
        if form.is_valid():
            new_password = form.cleaned_data["new_password1"]

            items = Item.objects.filter(owner=user)
            if items.exists():
                old_key = items.first().get_key()
                for item in items:
                    item.username = item.decrypt_field(old_key, item.username)
                    item.password = item.decrypt_field(old_key, item.password)
                    item.notes = item.decrypt_field(old_key, item.notes)

            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)

            if items.exists():
                for item in items:
                    new_key = item.get_key()
                    item.username = item.encrypt_field(new_key, item.username)
                    item.password = item.encrypt_field(new_key, item.password)
                    item.notes = item.encrypt_field(new_key, item.notes)
                    item.save()

            messages.success(request, "Your master password was successfully updated!")
            return redirect("vault:vault")
    else:
        form = MasterPasswordChangeForm(user=user)

    return render(request, "users/update_master_password.html", {"form": form})

@login_required
def delete_account(request):
    user = request.user
    user.delete()
    return redirect("users:register")


class CustomLoginView(LoginView):
    authentication_form = LoginForm
    def form_valid(self, form):
        user = form.get_user()
        if user.enable_2fa:
            self.request.session["user_id"] = user.id
            return redirect("users:2fa_verification")
        return super().form_valid(form)
