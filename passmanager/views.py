from django.shortcuts import render
from .models import Item


def home(request):
    return render(request, "passmanager/home.html")


def vault(request):
    items = Item.objects.all()
    context = {"items": items}
    return render(request, "passmanager/vault.html", context)
