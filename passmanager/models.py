from django.db import models
from django.conf import settings


class Item(models.Model):
    name = models.CharField(max_length=50)
    username = models.CharField(max_length=500)
    password = models.CharField(max_length=500)
    url = models.URLField(max_length=50)
    notes = models.TextField(max_length=1500)
    date_added = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
