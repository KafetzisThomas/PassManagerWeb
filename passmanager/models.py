from django.db import models


class Item(models.Model):
    name = models.CharField(max_length=100)
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    notes = models.TextField(max_length=100)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
