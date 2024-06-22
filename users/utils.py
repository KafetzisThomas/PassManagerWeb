from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string


def send_new_user_registration(user):
    subject = "Admin Notification: New User Registration"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = ["tomkafetzis06@gmail.com", "passmanagerweb@gmail.com"]

    html_message = render_to_string(
        "email_templates/new_user_registration.html",
        {
            "user_id": user.id,
            "user_email": user.email,
            "date_joined": user.date_joined.strftime("%d/%m/%Y %H:%M:%S"),
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)
