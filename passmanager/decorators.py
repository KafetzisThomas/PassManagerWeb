from django.shortcuts import render
from django.contrib.auth import authenticate, login
from users.forms import PasswordConfirmationForm


def reauth_required(view_func):
    """
    Force master password re-authentication before accessing the view.
    """

    def wrapper(request, *args, **kwargs):
        form = PasswordConfirmationForm(request.POST or None)
        if request.method == "POST" and form.is_valid():
            password = form.cleaned_data["password"]
            user = authenticate(email=request.user.email, password=password)
            if user is not None:
                login(request, user)  # refresh session
                return view_func(request, *args, **kwargs)
            form.add_error("password", "Invalid master password.")

        context = {"form": form}
        return render(request, "users/master_password_prompt.html", context)

    return wrapper
