from django.urls import path
from . import views

app_name = "passmanager"
urlpatterns = [
    path("", views.vault, name="vault"),
    path("item/new/", views.new_item, name="new_item"),
    path("item/<int:item_id>/edit", views.edit_item, name="edit_item"),
    path("csv/export/", views.export_csv, name="export_csv"),
    path("csv/import", views.import_csv, name="import_csv"),
    path("checkup/", views.checkup, name="checkup"),
    path("checkup/api/", views.checkup_api, name="checkup_api"),
]
