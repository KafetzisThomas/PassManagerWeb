# Generated by Django 4.2.15 on 2024-12-22 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_customuser_otp_secret'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='session_timeout',
            field=models.IntegerField(choices=[(300, '5 minutes'), (600, '10 minutes'), (900, '15 minutes'), (1800, '30 minutes'), (3600, '1 hour'), (10800, '3 hours')], default=900),
        ),
    ]
