# Generated by Django 4.2.18 on 2025-02-01 15:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_customuser_encryption_salt'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='encryption_salt',
            field=models.CharField(blank=True, max_length=44, null=True),
        ),
    ]
