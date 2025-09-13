from django.urls import path

from .views import (VaultView, NewItemView, EditItemView, delete_item,
                    password_generator, export_csv, import_csv, password_checkup)

app_name = "passmanager"
urlpatterns = [
    path("", VaultView.as_view(), name="vault"),
    path("new_item/", NewItemView.as_view(), name="new_item"),
    path("edit_item/<int:item_id>/", EditItemView.as_view(), name="edit_item"),
    path("edit_item/<int:item_id>/delete", delete_item, name="delete_item"),
    path("password_generator/", password_generator, name="password_generator"),
    path("export_csv/", export_csv, name="export_csv"),
    path("import_csv/", import_csv, name="import_csv"),
    path("password_checkup/", password_checkup, name="password_checkup"),
]
