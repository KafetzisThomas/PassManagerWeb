import pyotp
from django.shortcuts import render, redirect
from django.contrib.auth import login
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .utils import send_new_user_registration, send_2fa_verification
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
            login(
                request, new_user, backend="django.contrib.auth.backends.ModelBackend"
            )
            return redirect("vault")
    else:
        form = CustomUserCreationForm()

    context = {"form": form}
    return render(request, "registration/register.html", context)


@login_required
def account(request):
    if request.method == "POST":
        form = CustomUserChangeForm(instance=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(
                request, request.user
            )  # Important for keeping the user logged in
            messages.success(
                request, "Your account credentials was successfully updated!"
            )
            return redirect("users:account")
    else:
        form = CustomUserChangeForm(instance=request.user)

    context = {"form": form}
    return render(request, "users/account.html", context)


@login_required
def delete_account(request):
    user = CustomUser.objects.get(id=request.user.id)
    user.delete()
    return redirect("users:login")


class CustomLoginView(LoginView):
    authentication_form = CustomAuthenticationForm
