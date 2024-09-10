"""Defines URL patterns for passmanager"""

from django.urls import path
from . import views

app_name = "passmanager"
urlpatterns = [
    # Home page
    path("", views.home, name="home"),
    # FAQ page
    path("faq/", views.faq, name="faq"),
    # Vault page
    path("vault/", views.vault, name="vault"),
    # Add a new item page
    path("new_item/", views.new_item, name="new_item"),
    # Edit item page
    path("edit_item/<int:item_id>/", views.edit_item, name="edit_item"),
    # Delete item page
    path("edit_item/<int:item_id>/delete", views.delete_item, name="delete_item"),
    # Password generator page
    path("password_generator/", views.password_generator, name="password_generator"),
]
