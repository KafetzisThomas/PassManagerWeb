# Generated by Django 4.2.15 on 2024-12-21 13:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('passmanager', '0003_item_last_modified'),
    ]

    operations = [
        migrations.RenameField(
            model_name='item',
            old_name='website',
            new_name='url',
        ),
    ]
