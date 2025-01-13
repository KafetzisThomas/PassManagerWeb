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
)
from .utils import (
    send_new_user_registration,
    send_2fa_verification,
    send_delete_account_notification,
    send_update_account_notification,
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
        form = CustomUserChangeForm(instance=request.user, data=request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            new_password = form.cleaned_data["password1"]

            if new_password:
                items = Item.objects.filter(owner=user)
                for item in items:
                    # Decrypt fields with the old key
                    item.username = item.decrypt_field(item.get_key(), item.username)
                    item.password = item.decrypt_field(item.get_key(), item.password)
                    item.notes = item.decrypt_field(item.get_key(), item.notes)

                    # Update user's master password
                    user.set_password(new_password)

                    # Re-encrypt fields with the new key
                    item.owner = request.user
                    item.encrypt_sensitive_fields()
                    item.save()

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
                request, "Your account credentials was successfully updated!"
            )
            return redirect("passmanager:vault")
    else:
        form = CustomUserChangeForm(instance=request.user)

    context = {"form": form}
    return render(request, "users/account.html", context)


@login_required
def delete_account(request):
    user = CustomUser.objects.get(id=request.user.id)
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
