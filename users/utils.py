from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string


def send_new_user_registration(user):
    subject = "Admin Notification: New User Registration"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = ["passmanagerweb@gmail.com"]

    html_message = render_to_string(
        "email_templates/new_user_registration.html",
        {
            "user_id": user.id,
            "user_email": user.email,
            "date_joined": user.date_joined.strftime("%d/%m/%Y %H:%M:%S"),
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)


def send_2fa_verification(user, secret_key):
    subject = "Security Notification: 2FA Verification"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    html_message = render_to_string(
        "email_templates/2fa_verification.html",
        {
            "secret_key": secret_key,
            "user_email": user.email,
            "date_joined": user.date_joined.strftime("%d/%m/%Y %H:%M:%S"),
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)


def send_delete_account_notification(user):
    subject = "Security Notification: Your Account Has Been Deleted"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    html_message = render_to_string(
        "email_templates/delete_account_notification.html",
        {
            "user_email": user.email,
            "user_name": user.username,
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)


def send_update_account_notification(user):
    subject = "Security Notification: Your Account Settings Have Been Updated"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    html_message = render_to_string(
        "email_templates/update_account_notification.html",
        {
            "user_email": user.email,
            "user_name": user.username,
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)


def send_master_password_update(user):
    subject = "Security Notification: Master Password Updated"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    html_message = render_to_string(
        "email_templates/update_master_password.html",
        {
            "user_name": user.username,
        },
    )

    send_mail(subject, None, email_from, recipient_list, html_message=html_message)
