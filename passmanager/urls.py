"""Defines URL patterns for passmanager"""

from django.urls import path
from . import views

app_name = "passmanager"
urlpatterns = [
    # Vault page
    path("", views.vault, name="vault"),
    # Add a new item page
    path("new_item/", views.new_item, name="new_item"),
    # Edit item page
    path("edit_item/<int:item_id>/", views.edit_item, name="edit_item"),
    # Delete item page
    path("edit_item/<int:item_id>/delete", views.delete_item, name="delete_item"),
    # Password generator page
    path("password_generator/", views.password_generator, name="password_generator"),
    # Export csv page
    path("export_csv/", views.export_csv, name="export_csv"),
    # Import csv page
    path("import_csv/", views.import_csv, name="import_csv"),
    # Password checkup page
    path("password_checkup/", views.password_checkup, name="password_checkup"),
]
