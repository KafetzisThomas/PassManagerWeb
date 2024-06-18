"""Defines URL patterns for passmanager"""

from django.urls import path
from . import views

urlpatterns = [
    # Home page
    path("", views.home, name="home"),
]
