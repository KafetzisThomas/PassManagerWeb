import csv
import hashlib
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from .decorators import reauth_required
from .models import Item
from .forms import ItemForm, ImportDataForm

@login_required
def vault(request):
    search = request.GET.get("search")
    items = Item.objects.filter(owner=request.user).order_by("-date_added")

    if search:
        items = items.filter(name__icontains=search)

    context = {"items": items, "search_query": search}
    return render(request, "passmanager/vault.html", context)

@login_required
def new_item(request):
    if request.method == "POST":
        form = ItemForm(data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.owner = request.user
            obj.encrypt_sensitive_fields()
            obj.save()
            
            messages.success(request, "Item created successfully.")
            return redirect("passmanager:vault")
    else:
        form = ItemForm()

    return render(request, "passmanager/new_item.html", {"form": form})

@login_required
def edit_item(request, item_id):
    item = get_object_or_404(Item, id=item_id, owner=request.user)
    if request.method == "POST":
        if request.POST.get("action") == "delete":
            item.delete()
            messages.success(request, "Item deleted successfully.")
            return redirect("passmanager:vault")

        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.owner = request.user
            obj.encrypt_sensitive_fields()
            obj.save()
            messages.success(request, "Item modified successfully.")
            return redirect("passmanager:vault")
    else:
        item.decrypt_sensitive_fields()
        form = ItemForm(instance=item)

    return render(request, "passmanager/edit_item.html", {"item": item, "form": form})

@login_required
@reauth_required
def export_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="passmanagerweb_passwords.csv"'
    writer = csv.writer(response)
    writer.writerow(["name", "username", "password", "url", "notes"])

    data = Item.objects.filter(owner=request.user)
    for item in data:
        item.decrypt_sensitive_fields()
        writer.writerow([item.name, item.username, item.password, item.url, item.notes])

    return response

@login_required
def import_csv(request):
    if request.method == "POST":
        form = ImportDataForm(request.POST, request.FILES)
        if form.is_valid():
            csv_file = form.cleaned_data["csv_file"]
            file_data = csv_file.read().decode("utf-8").splitlines()
            csv_reader = csv.reader(file_data)

            # skip header row
            header = next(csv_reader)
            expected_header = ["name", "username", "password", "url", "notes"]

            if header != expected_header:
                messages.error(request, "Invalid CSV format. Please check the column names.")
                return redirect("passmanager:import_csv")

            for row in csv_reader:
                name, username, password, url, notes = row
                item = Item(name=name, username=username, password=password, url=url, notes=notes, owner=request.user)
                item.encrypt_sensitive_fields()
                item.save()

            messages.success(request, "Passwords imported successfully!")
            return redirect("passmanager:vault")
    else:
        form = ImportDataForm()

    return render(request, "passmanager/import_csv.html", {"form": form})

@login_required
def checkup(request):
    return render(request, "passmanager/checkup.html")

@login_required
def checkup_api(request):
    results = []
    items = Item.objects.filter(owner=request.user)
    for item in items:
        item.decrypt_sensitive_fields()
        if item.password:
            sha1_hash = hashlib.sha1(item.password.encode("utf-8")).hexdigest().upper()
            results.append({"name": item.name, "hash_prefix": sha1_hash[:5], "hash_suffix": sha1_hash[5:]})

    return JsonResponse({"items": results})
