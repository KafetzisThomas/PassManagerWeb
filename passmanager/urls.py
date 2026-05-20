from django.urls import path
from . import views

app_name = "passmanager"
urlpatterns = [
    path("", views.vault, name="vault"),
    path("new_item/", views.new_item, name="new_item"),
    path("edit_item/<int:item_id>/", views.edit_item, name="edit_item"),
    path("password_generator/", views.password_generator, name="password_generator"),
    path("export_csv/", views.export_csv, name="export_csv"),
    path("import_csv/", views.import_csv, name="import_csv"),
    path("password_checkup/", views.password_checkup, name="password_checkup"),
]
