# Generated by Django 4.2.15 on 2024-12-21 13:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('passmanager', '0005_alter_item_url'),
    ]

    operations = [
        migrations.AlterField(
            model_name='item',
            name='name',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='item',
            name='notes',
            field=models.TextField(max_length=1500),
        ),
        migrations.AlterField(
            model_name='item',
            name='password',
            field=models.CharField(max_length=500),
        ),
        migrations.AlterField(
            model_name='item',
            name='url',
            field=models.URLField(max_length=500),
        ),
        migrations.AlterField(
            model_name='item',
            name='username',
            field=models.CharField(max_length=500),
        ),
    ]
