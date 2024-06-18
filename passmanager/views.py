from django.shortcuts import render, redirect
from .models import Item
from .forms import ItemForm


def home(request):
    return render(request, "passmanager/home.html")


def vault(request):
    items = Item.objects.all()
    context = {"items": items}
    return render(request, "passmanager/vault.html", context)


def new_item(request):
    if request.method == "POST":
        form = ItemForm(data=request.POST)
        if form.is_valid():
            form.save()
            return redirect("vault")
    else:
        form = ItemForm()

    context = {"form": form}
    return render(request, "passmanager/new_item.html", context)


def edit_item(request, item_id):
    item = Item.objects.get(id=item_id)

    if request.method == "POST":
        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect("vault")
    else:
        form = ItemForm(instance=item)

    context = {"item": item, "form": form}
    return render(request, "passmanager/edit_item.html", context)
