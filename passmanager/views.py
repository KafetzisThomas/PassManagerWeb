import os
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import Item
from django.http import Http404
from .forms import ItemForm, PasswordGeneratorForm
from django.contrib import messages
from .utils import encrypt, decrypt, generate_password, check_password
from dotenv import load_dotenv

load_dotenv()


def home(request):
    return render(request, "passmanager/home.html")


@login_required
def vault(request):
    items = Item.objects.filter(owner=request.user).order_by("-date_added")
    paginator = Paginator(items, 3)  # Display 3 items per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    context = {"page_obj": page_obj}
    return render(request, "passmanager/vault.html", context)


@login_required
def new_item(request):
    if request.method == "POST":
        # Create a mutable copy of request.POST
        mutable_post_data = request.POST.copy()

        form = ItemForm(data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            website_entry = obj.website
            username_entry = obj.username
            password_entry = obj.password
            notes_entry = obj.notes

            if "gen_pass" in request.POST:
                generated_password = generate_password(
                    length=12,
                    include_letters=True,
                    include_digits=True,
                    include_special_chars=True,
                )

                # Update the mutable copy of POST data
                mutable_post_data["password"] = generated_password

                # Use the updated mutable_post_data to instantiate the form
                form = ItemForm(data=mutable_post_data)

                # Update the form's initial data for rendering
                form.initial["password"] = generated_password
                form.initial["website"] = website_entry
                form.initial["username"] = username_entry
                form.initial["notes"] = notes_entry

                context = {"form": form}
                return render(request, "passmanager/new_item.html", context)

            if "check_pass" in request.POST:
                is_pwned = check_password(mutable_post_data["password"])
                if mutable_post_data["password"]:
                    if is_pwned:
                        messages.error(
                            request,
                            f"This password has been exposed {is_pwned} time(s) in data leaks. You have to change it.",
                        )
                    else:
                        messages.success(
                            request,
                            "This password was not found in known data breaches. It must be safe to use.",
                        )

                context = {"form": form}
                return render(request, "passmanager/new_item.html", context)

            obj.website = encrypt(
                website_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.username = encrypt(
                username_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.password = encrypt(
                password_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.notes = encrypt(
                notes_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.owner = request.user

            form.save()
            return redirect("vault")
    else:
        form = ItemForm()

    context = {"form": form}
    return render(request, "passmanager/new_item.html", context)


@login_required
def edit_item(request, item_id):
    item = Item.objects.get(id=item_id)
    if item.owner != request.user:
        raise Http404

    if request.method == "POST":
        # Create a mutable copy of request.POST
        mutable_post_data = request.POST.copy()

        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)

            website_entry = obj.website
            username_entry = obj.username
            password_entry = obj.password
            notes_entry = obj.notes

            if "gen_pass" in request.POST:
                generated_password = generate_password(
                    length=12,
                    include_letters=True,
                    include_digits=True,
                    include_special_chars=True,
                )

                # Update the mutable copy of POST data
                mutable_post_data["password"] = generated_password

                # Use the updated mutable_post_data to instantiate the form
                form = ItemForm(data=mutable_post_data)

                # Update the form's initial data for rendering
                form.initial["password"] = generated_password
                form.initial["website"] = website_entry
                form.initial["username"] = username_entry
                form.initial["notes"] = notes_entry

                context = {"item": item, "form": form}
                return render(request, "passmanager/edit_item.html", context)

            if "check_pass" in request.POST:
                is_pwned = check_password(mutable_post_data["password"])
                if mutable_post_data["password"]:
                    if is_pwned:
                        messages.error(
                            request,
                            f"This password has been exposed {is_pwned} time(s) in data leaks. You have to change it.",
                        )
                    else:
                        messages.success(
                            request,
                            "This password was not found in known data breaches. It must be safe to use.",
                        )

                context = {"item": item, "form": form}
                return render(request, "passmanager/edit_item.html", context)

            obj.website = encrypt(
                website_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.username = encrypt(
                username_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.password = encrypt(
                password_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.notes = encrypt(
                notes_entry.encode(), os.getenv("ENCRYPTION_KEY")
            ).decode("utf-8")
            obj.owner = request.user

            form.save()
            return redirect("vault")
    else:
        # Decrypt the fields for display in the form
        decrypted_website = decrypt(
            item.website.encode(), os.getenv("ENCRYPTION_KEY")
        ).decode("utf-8")
        decrypted_username = decrypt(
            item.username.encode(), os.getenv("ENCRYPTION_KEY")
        ).decode("utf-8")
        decrypted_password = decrypt(
            item.password.encode(), os.getenv("ENCRYPTION_KEY")
        ).decode("utf-8")
        decrypted_notes = decrypt(
            item.notes.encode(), os.getenv("ENCRYPTION_KEY")
        ).decode("utf-8")

        initial_data = {
            "name": item.name,
            "website": decrypted_website,
            "username": decrypted_username,
            "password": decrypted_password,
            "notes": decrypted_notes,
        }
        form = ItemForm(instance=item, initial=initial_data)

    context = {"item": item, "form": form}
    return render(request, "passmanager/edit_item.html", context)


@login_required
def delete_item(request, item_id):
    item = Item.objects.get(id=item_id)
    if item.owner != request.user:
        raise Http404
    item.delete()
    return redirect("vault")


def password_generator(request):
    form = PasswordGeneratorForm()
    password = ""  # Initialize password variable

    if request.method == "POST":
        form = PasswordGeneratorForm(request.POST)
        if form.is_valid():
            length = form.cleaned_data["length"]
            include_letters = form.cleaned_data["letters"]
            include_digits = form.cleaned_data["digits"]
            include_special_chars = form.cleaned_data["special_chars"]
            password = generate_password(
                length, include_letters, include_digits, include_special_chars
            )

    context = {"form": form, "password": password}

    return render(
        request,
        "passmanager/password_generator.html",
        context,
    )
