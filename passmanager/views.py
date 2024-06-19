import os
import string
import random
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import Item
from django.http import Http404
from .forms import ItemForm, PasswordGeneratorForm
from .utils import encrypt, decrypt
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
        form = ItemForm(data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            website_entry = obj.website
            username_entry = obj.username
            password_entry = obj.password
            notes_entry = obj.notes

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
        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)

            website_entry = obj.website
            username_entry = obj.username
            password_entry = obj.password
            notes_entry = obj.notes

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


def generate_password(length, include_letters, include_digits, include_special_chars):
    characters = ""
    if include_letters:
        characters += string.ascii_letters
    if include_digits:
        characters += string.digits
    if include_special_chars:
        characters += string.punctuation
    return "".join(random.choice(characters) for _ in range(length))


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
