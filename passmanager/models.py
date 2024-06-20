from django.db import models
from django.conf import settings


class Item(models.Model):
    name = models.CharField(max_length=100)
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    notes = models.TextField(max_length=100)
    date_added = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
