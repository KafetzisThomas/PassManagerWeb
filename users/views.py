import pyotp
from django.shortcuts import render, redirect
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .utils import (
    send_new_user_registration,
    send_2fa_verification,
    send_delete_account_notification,
    send_update_account_notification,
)
from django.contrib.auth.views import LoginView
from .forms import CustomAuthenticationForm


def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(data=request.POST)
        if form.is_valid():
            otp_secret = pyotp.random_base32()
            new_user = form.save(commit=False)
            new_user.otp_secret = otp_secret
            form.save()
            send_new_user_registration(new_user)
            send_2fa_verification(new_user, otp_secret)
            messages.success(
                request,
                "Account successfully created! An email containing your OTP key has been sent to your inbox.",
            )
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
            user = CustomUser.objects.get(id=request.user.id)
            send_update_account_notification(user)
            form.save()
            update_session_auth_hash(
                request, request.user
            )  # Important for keeping the user logged in
            messages.success(
                request, "Your account credentials was successfully updated!"
            )
            return redirect("vault")
    else:
        form = CustomUserChangeForm(instance=request.user)

    context = {"form": form}
    return render(request, "users/account.html", context)


@login_required
def delete_account(request):
    user = CustomUser.objects.get(id=request.user.id)
    user.delete()
    send_delete_account_notification(user)
    return redirect("home")


class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm
