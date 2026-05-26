from django.shortcuts import render
from users.forms import PasswordConfirmationForm

def reauth_required(view_func):
    def wrapper(request, *args, **kwargs):
        form = PasswordConfirmationForm(user=request.user, data=request.POST or None)
        if request.method == "POST" and form.is_valid():
            return view_func(request, *args, **kwargs)

        return render(request, "users/master_password_prompt.html", {"form": form})

    return wrapper
