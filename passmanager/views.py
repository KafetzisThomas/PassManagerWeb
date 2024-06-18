from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Item
from .forms import ItemForm


def home(request):
    return render(request, "passmanager/home.html")


@login_required
def vault(request):
    items = Item.objects.filter(owner=request.user).order_by("date_added")
    context = {"items": items}
    return render(request, "passmanager/vault.html", context)


@login_required
def new_item(request):
    if request.method == "POST":
        form = ItemForm(data=request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
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

    if request.method == "POST":
        form = ItemForm(instance=item, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect("vault")
    else:
        form = ItemForm(instance=item)

    context = {"item": item, "form": form}
    return render(request, "passmanager/edit_item.html", context)
