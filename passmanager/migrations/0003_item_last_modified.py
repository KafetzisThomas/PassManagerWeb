# Generated by Django 4.2.15 on 2024-12-19 20:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('passmanager', '0002_item_owner'),
    ]

    operations = [
        migrations.AddField(
            model_name='item',
            name='last_modified',
            field=models.DateTimeField(auto_now=True),
        ),
    ]