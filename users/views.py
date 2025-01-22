import pyotp
from passmanager.models import Item
from django.shortcuts import render, redirect
from django.views.generic.edit import FormView
from django.contrib.auth.views import LoginView
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser
from .forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    TwoFactorVerificationForm,
    CustomUserChangeForm,
    MasterPasswordChangeForm,
)
from .utils import (
    send_new_user_registration,
    send_2fa_verification,
    send_delete_account_notification,
    send_update_account_notification,
    send_master_password_update,
)


def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(data=request.POST)
        if form.is_valid():
            new_user = form.save()
            send_new_user_registration(new_user)
            messages.success(request, "Account successfully created!")
            return redirect("users:login")
    else:
        form = CustomUserCreationForm()

    context = {"form": form}
    return render(request, "registration/register.html", context)


@login_required
def account(request):
    if request.method == "POST":
        action = request.POST.get("action")
        form = CustomUserChangeForm(instance=request.user, data=request.POST)

        if form.is_valid():
            if action == "save":
                user = form.save(commit=False)

                # Handle 2FA enable/disable & OTP secret generation
                user.enable_2fa = form.cleaned_data.get("enable_2fa", False)
                if user.enable_2fa:
                    user.otp_secret = pyotp.random_base32()
                    send_2fa_verification(user, user.otp_secret)
                    messages.success(
                        request, "2FA enabled! Check your email for the OTP key."
                    )
                else:
                    user.otp_secret = ""

                user.save()
                send_update_account_notification(user)
                update_session_auth_hash(
                    request, request.user
                )  # Important for keeping the user logged in
                messages.success(
                    request, "Your account credentials were successfully updated!"
                )
                return redirect("passmanager:vault")
            elif action == "update_master_password":
                return redirect("users:update_master_password")
            elif action == "export_data":
                return redirect("passmanager:download_csv")
        else:
            messages.error(request, "There was an error updating your account.")
    else:
        form = CustomUserChangeForm(instance=request.user)

    context = {"form": form}
    return render(request, "users/account.html", context)


@login_required
def update_master_password(request):
    if request.method == "POST":
        form = MasterPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            old_password = form.cleaned_data["old_password"]
            new_password = form.cleaned_data["new_password1"]

            # Authenticate old password
            if not request.user.check_password(old_password):
                messages.error(request, "Old master password is incorrect.")
                return redirect("users:update_master_password")

            user = request.user
            items = Item.objects.filter(owner=user)

            if items.exists():
                old_key = items.first().get_key()
                for item in items:
                    # Decrypt fields with the old key
                    item.username = item.decrypt_field(old_key, item.username)
                    item.password = item.decrypt_field(old_key, item.password)
                    item.notes = item.decrypt_field(old_key, item.notes)

            # Update user's master password
            user.set_password(new_password)
            user.save()

            # Re-encrypt fields with the new key
            if items.exists():
                for item in items:
                    new_key = item.get_key()
                    item.username = item.encrypt_field(new_key, item.username)
                    item.password = item.encrypt_field(new_key, item.password)
                    item.notes = item.encrypt_field(new_key, item.notes)
                    item.save()

            send_master_password_update(user)
            messages.success(request, "Your master password was successfully updated!")
            return redirect("passmanager:vault")
    else:
        form = MasterPasswordChangeForm(user=request.user)

    context = {"form": form}
    return render(request, "users/update_master_password.html", context)


@login_required
def delete_account(request):
    user = request.user
    user.delete()
    send_delete_account_notification(user)
    return redirect("passmanager:home")


class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm

    def form_valid(self, form):
        user = form.cleaned_data["user"]
        if user.otp_secret:
            self.request.session["user_id"] = user.id  # Store user ID in session
            return redirect("users:2fa_verification")
        return super().form_valid(form)


class TwoFactorVerificationView(FormView):
    template_name = "registration/2fa_verification.html"
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

        # Remove user from session data
        self.request.session.pop("user_id", None)
        return redirect("passmanager:vault")
