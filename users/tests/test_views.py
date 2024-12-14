"""
This module contains test cases for the following views:
* register, account, delete_account
"""

import os
import csv
import base64
from django.test import TestCase, Client, override_settings
from unittest.mock import MagicMock, patch
from django.urls import reverse
from django.contrib.auth import SESSION_KEY
from django.contrib.messages import get_messages
from django.contrib.auth.hashers import check_password
from ..forms import CustomUserCreationForm, CustomUserChangeForm
from ..models import CustomUser

from passmanager.models import Item
from passmanager.utils import encrypt, decrypt


@patch("turnstile.fields.TurnstileField.validate", return_value=True)
class RegisterViewTest(TestCase):
    """
    Test case for the register view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.register_url = reverse("users:register")

    def test_register_view_get(self, mock: MagicMock):
        """
        Test that the register view returns the registration form on GET request.
        """
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/register.html")
        self.assertIsInstance(response.context["form"], CustomUserCreationForm)

    def test_register_view_post_valid_form(self, mock: MagicMock):
        """
        Test registering a new user with a valid form submission.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "testpassword123",
            "captcha_verification": "testsecret",
        }
        response = self.client.post(self.register_url, form_data)
        self.assertRedirects(response, reverse("users:login"))

        # Check if the user is created in the database
        self.assertTrue(
            CustomUser.objects.filter(email="testuser@example.com").exists()
        )

        # Check that the OTP secret is generated and saved for the new user
        new_user = CustomUser.objects.get(email="testuser@example.com")
        self.assertIsNotNone(new_user.otp_secret)
        self.assertIsInstance(new_user.otp_secret, str)

        # Check success message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].tags, "success")
        self.assertEqual(
            str(messages[0]),
            "Account successfully created! An email containing your OTP key has been sent to your inbox.",
        )

        # Check if the user is still logged out
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_register_view_post_invalid_form(self, mock: MagicMock):
        """
        Test registering a new user with an invalid form submission.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "wrongpassword",
            "captcha_verification": "testsecret",
        }
        response = self.client.post(self.register_url, form_data)
        self.assertEqual(response.status_code, 200)

        # Check form errors for password2 field
        form = response.context["form"]
        self.assertTrue(form.has_error("password2", code="password_mismatch"))

        # Check that user is not created in the database
        self.assertFalse(
            CustomUser.objects.filter(email="testuser@example.com").exists()
        )


class AccountViewTest(TestCase):
    """
    Test case for the account view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")
        self.account_url = reverse("users:account")

    def test_account_view_get(self):
        """
        Test rendering the account page with GET request.
        """
        response = self.client.get(self.account_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/account.html")
        self.assertIsInstance(response.context["form"], CustomUserChangeForm)
        self.assertEqual(response.context["form"].instance, self.user)

    def test_account_view_post_valid_form(self):
        """
        Test updating account credentials with valid form data.
        """
        form_data = {
            "email": "updateduser@example.com",
            "username": "updateduser",
            "password1": "newpassword123",
            "password2": "newpassword123",
        }
        response = self.client.post(self.account_url, form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if user details are updated
        updated_user = CustomUser.objects.get(email="updateduser@example.com")
        self.assertEqual(updated_user.username, "updateduser")
        self.assertTrue(check_password("newpassword123", updated_user.password))

        # Check success message
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].tags, "success")
        self.assertEqual(
            str(messages[0]), "Your account credentials was successfully updated!"
        )

    def test_account_view_post_invalid_form(self):
        """
        Test handling of invalid form submission.
        """
        form_data = {
            "email": "updateduser@example.com",
            "username": "updateduser",
            "password1": "newpassword123",
            "password2": "wrongpassword",
        }
        response = self.client.post(self.account_url, form_data)
        self.assertEqual(response.status_code, 200)

        # Check that the form errors are displayed
        self.assertFormError(response, "form", "password2", "Passwords do not match.")

        # Ensure user details remain unchanged
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "testuser@example.com")
        self.assertEqual(self.user.username, "testuser")

    def test_account_view_post_no_changes(self):
        """
        Test submitting the form with no changes.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "",
            "password2": "",
        }
        response = self.client.post(self.account_url, form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Ensure user details remain unchanged
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "testuser@example.com")
        self.assertEqual(self.user.username, "testuser")

    def test_account_view_not_logged_in(self):
        """
        Test accessing the view when not logged in.
        """
        self.client.logout()
        response = self.client.get(self.account_url)
        self.assertRedirects(response, f"/user/login/?next=/user/account/")


class DeleteAccountViewTest(TestCase):
    """
    Test case for the delete_account view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")
        self.delete_account_url = reverse("users:delete_account")

    def test_delete_account_view(self):
        """
        Test deleting the user account with a POST request.
        """
        response = self.client.post(self.delete_account_url)
        self.assertRedirects(response, reverse("passmanager:home"))

        # Check that the user is deleted
        self.assertFalse(CustomUser.objects.filter(id=self.user.id).exists())

    def test_delete_account_view_not_logged_in(self):
        """
        Test accessing the view when not logged in.
        """
        self.client.logout()
        response = self.client.post(self.delete_account_url)
        self.assertRedirects(
            response, f"/user/login/?next=/user/account/delete_account/"
        )

        # Ensure the user is not deleted
        self.assertTrue(CustomUser.objects.filter(id=self.user.id).exists())


class DownloadCsvViewTest(TestCase):
    """
    Test case for the download_csv view.
    """

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.client = Client()
        self.encryption_key = os.getenv("ENCRYPTION_KEY").encode()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")
        self.item = Item.objects.create(
            name="Test Item",
            website=encrypt("http://example.com".encode(), self.encryption_key).decode(
                "utf-8"
            ),
            username=encrypt("testuser".encode(), self.encryption_key).decode("utf-8"),
            password=encrypt("testpassword".encode(), self.encryption_key).decode(
                "utf-8"
            ),
            notes=encrypt("Test notes".encode(), self.encryption_key).decode("utf-8"),
            owner=self.user,
        )

    @override_settings(ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)))
    def test_download_csv(self):
        """
        Test csv file returns with properly decrypted user data.
        """
        response = self.client.get(reverse("passmanager:download_csv"))

        # Verify response status & headers
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("PassManager Passwords.csv", response["Content-Disposition"])

        # Decode csv content & validate header
        content = response.content.decode("utf-8")
        reader = csv.reader(content.splitlines())
        header = next(reader)
        self.assertEqual(header, ["name", "website", "username", "password", "notes"])

        # Validate decrypted csv data rows
        rows = list(reader)
        self.assertEqual(len(rows), 1)  # Only 1 row of data

        decrypted_website = decrypt(
            self.item.website.encode(), self.encryption_key
        ).decode("utf-8")
        decrypted_username = decrypt(
            self.item.username.encode(), self.encryption_key
        ).decode("utf-8")
        decrypted_password = decrypt(
            self.item.password.encode(), self.encryption_key
        ).decode("utf-8")
        decrypted_notes = decrypt(self.item.notes.encode(), self.encryption_key).decode(
            "utf-8"
        )

        self.assertEqual(
            rows[0],
            [
                "Test Item",
                decrypted_website,
                decrypted_username,
                decrypted_password,
                decrypted_notes,
            ],
        )
