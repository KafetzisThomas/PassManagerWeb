"""Defines URL patterns for passmanager"""

from django.urls import path
from . import views

urlpatterns = [
    # Home page
    path("", views.home, name="home"),
    # Vault page
    path("vault/", views.vault, name="vault"),
    # Add a new item page
    path("new_item/", views.new_item, name="new_item"),
]
