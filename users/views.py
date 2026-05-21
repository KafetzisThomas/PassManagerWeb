import pyotp
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.views.generic.edit import FormView
from django.contrib import messages
from .models import CustomUser
from passmanager.models import Item
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

def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account successfully created!")
            return redirect("users:login")
    else:
        form = RegistrationForm()
    return render(request, "users/register.html", {"form": form})

@login_required
def account(request):
    email_form = EmailUpdateForm(instance=request.user)
    username_form = UsernameUpdateForm(instance=request.user)
    session_form = SessionTimeoutUpdateForm(instance=request.user)
    tfa_form = TwoFactorToggleForm(instance=request.user)

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "update_email":
            email_form = EmailUpdateForm(request.POST, instance=request.user)
            if email_form.is_valid():
                email_form.save()
                messages.success(request, "Email updated successfully.")
                return redirect("users:account")

        elif action == "update_username":
            username_form = UsernameUpdateForm(request.POST, instance=request.user)
            if username_form.is_valid():
                username_form.save()
                messages.success(request, "Username updated successfully.")
                return redirect("users:account")

        elif action == "update_session":
            session_form = SessionTimeoutUpdateForm(request.POST, instance=request.user)
            if session_form.is_valid():
                session_form.save()
                messages.success(request, "Session timeout updated successfully.")
                return redirect("users:account")

        elif action == "toggle_2fa":
            tfa_form = TwoFactorToggleForm(request.POST, instance=request.user)
            if tfa_form.is_valid():
                user = tfa_form.save(commit=False)
                if user.enable_2fa:
                    user.otp_secret = pyotp.random_base32()
                    messages.success(request, "2FA enabled!")
                else:
                    user.otp_secret = ""
                    messages.success(request, "2FA disabled.")

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
    authentication_form = LoginForm
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
