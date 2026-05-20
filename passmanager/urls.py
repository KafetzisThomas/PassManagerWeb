from django.urls import path
from . import views

app_name = "passmanager"
urlpatterns = [
    path("", views.vault, name="vault"),
    path("item/new/", views.new_item, name="new_item"),
    path("item/<int:item_id>/edit", views.edit_item, name="edit_item"),
    path("generator/", views.password_generator, name="password_generator"),
    path("csv/export/", views.export_csv, name="export_csv"),
    path("csv/import", views.import_csv, name="import_csv"),
    path("checkup/", views.password_checkup, name="password_checkup"),
]
