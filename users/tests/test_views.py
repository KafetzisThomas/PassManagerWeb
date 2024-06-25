"""
This module contains test cases for the following views:
* register, account
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import authenticate
from django.contrib.messages import get_messages
from django.contrib.auth.hashers import check_password
from ..forms import CustomUserCreationForm, CustomUserChangeForm
from ..models import CustomUser


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

    def test_register_view_get(self):
        """
        Test that the register view returns the registration form on GET request.
        """
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/register.html")
        self.assertIsInstance(response.context["form"], CustomUserCreationForm)

    def test_register_view_post_valid_form(self):
        """
        Test registering a new user with a valid form submission.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "testpassword123",
        }
        response = self.client.post(self.register_url, form_data)
        self.assertRedirects(response, reverse("vault"))

        # Check if the user is created in the database
        self.assertTrue(
            CustomUser.objects.filter(email="testuser@example.com").exists()
        )

        # Check if the user is logged in
        user = authenticate(email="testuser@example.com", password="testpassword123")
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "testuser@example.com")

    def test_register_view_post_invalid_form(self):
        """
        Test registering a new user with an invalid form submission.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "wrongpassword",
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

    def test_register_view_otp_secret_generation(self):
        """
        Test that an OTP secret is generated and stored when a new user is registered.
        """
        form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "testpassword123",
        }
        response = self.client.post(self.register_url, form_data)
        self.assertRedirects(response, reverse("vault"))

        # Check that the OTP secret is generated and saved for the new user
        new_user = CustomUser.objects.get(email="testuser@example.com")
        self.assertIsNotNone(new_user.otp_secret)
        self.assertIsInstance(new_user.otp_secret, str)


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
        self.assertRedirects(response, reverse("users:account"))

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
        self.assertRedirects(response, reverse("users:account"))

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
