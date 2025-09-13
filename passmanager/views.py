import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from dotenv import load_dotenv

from .decorators import reauth_required
from .forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm
from .models import Item
from .utils import check_pwned_password, generate_password

load_dotenv()

@login_required
def vault(request):
    # Retrieve selected group & search query,
    # from the query parameters
    selected_group = request.GET.get("group")
    search_query = request.GET.get("search_query")
    items = Item.objects.filter(owner=request.user).order_by("name")
    groups = (
        Item.objects.filter(owner=request.user)
        .values_list("group", flat=True)
        .distinct()
    )

    # Filter items by group if a group is selected
    if selected_group:
        items = items.filter(group=selected_group)

    # Filter items by search query if input is provided
    if search_query:
        items = items.filter(name__icontains=search_query)

    context = {"items": items, "groups": groups, "selected_group": selected_group, "search_query": search_query}
    return render(request, "passmanager/vault.html", context)

@login_required
def new_item(request):
    if request.method == "POST":
        # Create a mutable copy of request.POST
        mutable_post_data = request.POST.copy()
        form = ItemForm(data=request.POST)
        obj = form.save(commit=False)

        username_entry = obj.username
        notes_entry = obj.notes

        if form.is_valid():
            action = request.POST.get("action", "value")
            if action == "save":
                obj = form.save(commit=False)
                obj.owner = request.user
                obj.encrypt_sensitive_fields()
                obj.save()
                messages.success(request, "Item created successfully.")
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
                form.initial["username"] = username_entry
                form.initial["password"] = generated_password
                form.initial["notes"] = notes_entry

                context = {"form": form}
                messages.success(
                    request, "New password has been generated successfully."
                )

                return render(request, "passmanager/new_item.html", context)
    else:
        form = ItemForm()

    return render(request, "passmanager/new_item.html", {"form": form})

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
            username_entry = obj.username
            notes_entry = obj.notes

            if action == "save":
                obj = form.save(commit=False)
                obj.owner = request.user
                obj.encrypt_sensitive_fields()
                obj.save()
                messages.success(request, "Item modified successfully.")
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
                form.initial["username"] = username_entry
                form.initial["password"] = generated_password
                form.initial["notes"] = notes_entry

                context = {"item": item, "form": form}
                messages.success(
                    request, "New password has been generated successfully."
                )

                return render(request, "passmanager/edit_item.html", context)
        else:
            messages.error(
                request,
                "The item could not be changed because the data didn't validate.",
            )

    else:
        item.decrypt_sensitive_fields()
        form = ItemForm(instance=item)

    return render(request, "passmanager/edit_item.html", {"item": item, "form": form})

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
    return render(request, "passmanager/password_generator.html", context)

@login_required
@reauth_required
def export_csv(request):
    # Create response with csv content type & set filename for download
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="PassManager Passwords.csv"'
    writer = csv.writer(response)

    # Write csv header (column names)
    writer.writerow(["name", "username", "password", "url", "notes", "group"])

    # Fetch user-specific data
    data = Item.objects.filter(owner=request.user)

    for item in data:
        item.decrypt_sensitive_fields()
        writer.writerow(
            [item.name, item.username, item.password, item.url, item.notes, item.group]
        )

    return response

@login_required
def import_csv(request):
    if request.method == "POST":
        form = ImportPasswordsForm(request.POST, request.FILES)
        if form.is_valid():
            # Read the uploaded file
            csv_file = form.cleaned_data["csv_file"]
            file_data = csv_file.read().decode("utf-8").splitlines()
            csv_reader = csv.reader(file_data)

            # Skip the header row
            header = next(csv_reader)
            expected_header = ["name", "username", "password", "url", "notes", "group"]

            if header != expected_header:
                messages.error(
                    request, "Invalid CSV format. Please check the column names."
                )
                return redirect("passmanager:import_csv")

            for row in csv_reader:
                name, username, password, url, notes, group = row
                item = Item(
                    name=name,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes,
                    group=group,
                    owner=request.user,
                )
                item.encrypt_sensitive_fields()
                item.save()

            messages.success(request, "Passwords imported successfully!")
            return redirect("passmanager:vault")
    else:
        form = ImportPasswordsForm()

    return render(request, "passmanager/import_csv.html", {"form": form})

@login_required
def password_checkup(request):
    items = Item.objects.filter(owner=request.user)
    results = []
    for item in items:
        item.decrypt_sensitive_fields()
        password_status = check_pwned_password(item.password) if item.password else None
        if password_status:
            results.append(
                {
                    "name": item.name,
                    "status": f"Exposed {password_status} time(s)",
                    "recommendation": "Changing this password is recommended.",
                    "severity": "High",
                }
            )
        else:
            results.append(
                {
                    "name": item.name,
                    "status": "No breaches found.",
                    "recommendation": "This password appears to be safe.",
                    "severity": "Low",
                }
            )

    return render(request, "passmanager/password_checkup.html", {"results": results})
