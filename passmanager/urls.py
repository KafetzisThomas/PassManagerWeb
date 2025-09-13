from django.urls import path

from .views import (vault, new_item, edit_item, delete_item,
                    password_generator, export_csv, import_csv, password_checkup)

app_name = "passmanager"
urlpatterns = [
    path("", vault, name="vault"),
    path("new_item/", new_item, name="new_item"),
    path("edit_item/<int:item_id>/", edit_item, name="edit_item"),
    path("edit_item/<int:item_id>/delete", delete_item, name="delete_item"),
    path("password_generator/", password_generator, name="password_generator"),
    path("export_csv/", export_csv, name="export_csv"),
    path("import_csv/", import_csv, name="import_csv"),
    path("password_checkup/", password_checkup, name="password_checkup"),
]
