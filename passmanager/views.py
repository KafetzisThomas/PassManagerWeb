import os
import csv
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from .models import Item
from django.http import Http404, HttpResponse
from .forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm
from django.contrib import messages
from .utils import encrypt, decrypt, check_password, generate_password
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
        # Create a mutable copy of request.POST
        mutable_post_data = request.POST.copy()
        form = ItemForm(data=request.POST)
        obj = form.save(commit=False)

        website_entry = obj.website
        username_entry = obj.username
        password_entry = obj.password
        notes_entry = obj.notes

        if form.is_valid():
            action = request.POST.get("action", "value")
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
                    "Item created successfully.",
                )
                return redirect("passmanager:vault")

            elif action == "generate_password":
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
                messages.success(
                    request, "New password has been generated successfully."
                )
                return render(request, "passmanager/new_item.html", context)

            elif action == "check_password":
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
                else:
                    messages.error(request, "No password to check.")

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
            return redirect("passmanager:vault")

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
                return redirect("passmanager:vault")

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
                messages.success(
                    request, "New password has been generated successfully."
                )
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
                    messages.error(request, "No password to check.")

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
    return redirect("passmanager:vault")


@login_required
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


@login_required
def download_csv(request):
    # Create response with csv content type & set filename for download
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="PassManager Passwords.csv"'
    writer = csv.writer(response)

    # Write csv header (column names)
    writer.writerow(["name", "website", "username", "password", "notes"])

    # Fetch user-specific data
    data = Item.objects.filter(owner=request.user)

    for item in data:
        decrypted_website = decrypt(item.website, os.getenv("ENCRYPTION_KEY")).decode(
            "utf-8"
        )
        decrypted_username = decrypt(item.username, os.getenv("ENCRYPTION_KEY")).decode(
            "utf-8"
        )
        decrypted_password = decrypt(item.password, os.getenv("ENCRYPTION_KEY")).decode(
            "utf-8"
        )
        decrypted_notes = decrypt(item.notes, os.getenv("ENCRYPTION_KEY")).decode(
            "utf-8"
        )

        writer.writerow(
            [
                item.name,
                decrypted_website,
                decrypted_username,
                decrypted_password,
                decrypted_notes,
            ]
        )

    return response


@login_required
def upload_csv(request):
    if request.method == "POST":
        form = ImportPasswordsForm(request.POST, request.FILES)
        if form.is_valid():
            # Read the uploaded file
            csv_file = form.cleaned_data["csv_file"]
            file_data = csv_file.read().decode("utf-8").splitlines()
            csv_reader = csv.reader(file_data)

            # Skip the header row
            header = next(csv_reader)
            expected_header = ["name", "website", "username", "password", "notes"]

            if header != expected_header:
                messages.error(
                    request, "Invalid CSV format. Please check the column names."
                )
                return redirect("passmanager:upload_csv")

            for row in csv_reader:
                name, website, username, password, notes = row

                # Encrypt fields before saving
                encrypted_website = encrypt(
                    website.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                encrypted_username = encrypt(
                    username.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                encrypted_password = encrypt(
                    password.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")
                encrypted_notes = encrypt(
                    notes.encode(), os.getenv("ENCRYPTION_KEY")
                ).decode("utf-8")

                Item.objects.create(
                    name=name,
                    website=encrypted_website,
                    username=encrypted_username,
                    password=encrypted_password,
                    notes=encrypted_notes,
                    owner=request.user,
                )

            messages.success(request, "Passwords imported successfully!")
            return redirect("passmanager:vault")
    else:
        form = ImportPasswordsForm()

    context = {"form": form}
    return render(request, "passmanager/upload_csv.html", context)
