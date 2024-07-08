import os
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import Item
from django.http import Http404
from .forms import ItemForm, PasswordGeneratorForm
from django.contrib import messages
from .utils import encrypt, decrypt, check_password
from pass_generator.pass_generator import generate_password
from dotenv import load_dotenv

load_dotenv()


def home(request):
    return render(request, "passmanager/home.html")


def faq(request):
    return render(request, "passmanager/faq.html")


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
        form = ItemForm(request.POST)

        if form.is_valid():
            action = request.POST.get("action")

            if action == "save":
                obj = form.save(commit=False)
                obj.website = encrypt(
                    obj.website.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                obj.username = encrypt(
                    obj.username.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                obj.password = encrypt(
                    obj.password.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                obj.notes = encrypt(
                    obj.notes.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                obj.owner = request.user
                obj.save()

                messages.success(request, "Item created successfully.")
                return redirect("vault")

            elif action == "generate_password":
                generated_password = generate_password(
                    length=12,
                    include_letters=True,
                    include_digits=True,
                    include_special_chars=True,
                )

                form = ItemForm(
                    initial={
                        "name": form.cleaned_data["name"],
                        "website": form.cleaned_data["website"],
                        "username": form.cleaned_data["username"],
                        "notes": form.cleaned_data["notes"],
                        "password": generated_password,
                    }
                )

                messages.success(request, "Generated a new password.")
                context = {"form": form}
                return render(request, "passmanager/new_item.html", context)

            elif action == "check_password":
                password = form.cleaned_data["password"]
                if password:
                    is_pwned = check_password(password)
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
                else:
                    messages.error(request, "No password provided for checking.")

                context = {"form": form}
                return render(request, "passmanager/new_item.html", context)

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
        action = request.POST.get("action")

        if action == "delete":
            delete_item(request, item.id)
            messages.success(
                request,
                "Item deleted successfully.",
            )
            return redirect("vault")

        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            website_entry = obj.website
            username_entry = obj.username
            password_entry = obj.password
            notes_entry = obj.notes

            if action == "save":
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
                messages.success(
                    request,
                    "Item modified successfully.",
                )
                return redirect("vault")

            elif action == "generate_password":
                generated_password = generate_password(
                    length=12,
                    include_letters=True,
                    include_digits=True,
                    include_special_chars=True,
                )

                form = ItemForm(instance=item)

                # Update the form's initial data for rendering
                form.initial["password"] = generated_password
                form.initial["website"] = website_entry
                form.initial["username"] = username_entry
                form.initial["notes"] = notes_entry

                context = {"item": item, "form": form}
                messages.success(request, "Generated a new password.")
                return render(request, "passmanager/edit_item.html", context)

            elif action == "check_password":
                is_pwned = check_password(password_entry)
                if password_entry:
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
                else:
                    messages.error(request, "No password provided for checking.")

                context = {"item": item, "form": form}
                return render(request, "passmanager/edit_item.html", context)

        else:
            messages.error(
                request,
                "The item could not be changed because the data didn't validate.",
            )

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
