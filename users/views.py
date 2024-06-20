from django.shortcuts import render, redirect
from django.contrib.auth import login
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomUserChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages


def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(data=request.POST)
        if form.is_valid():
            new_user = form.save()
            login(request, new_user)
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
