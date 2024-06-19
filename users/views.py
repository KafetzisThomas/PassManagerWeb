from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .forms import UpdateUserForm
from django.contrib.auth.decorators import login_required


def register(request):
    if request.method == "POST":
        form = UserCreationForm(data=request.POST)
        if form.is_valid():
            new_user = form.save()
            login(request, new_user)
            return redirect("vault")
    else:
        form = UserCreationForm()

    context = {"form": form}
    return render(request, "registration/register.html", context)


@login_required
def account(request):
    if request.method == "POST":
        form = UpdateUserForm(instance=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect("users:account")
    else:
        form = UpdateUserForm(instance=request.user)

    context = {"form": form}
    return render(request, "users/account.html", context)


@login_required
def delete_account(request):
    user = User.objects.get(id=request.user.id)
    user.delete()
    return redirect("users:login")
