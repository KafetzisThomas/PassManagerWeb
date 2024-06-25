"""
This module contains test cases for the following views:
* register
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import authenticate
from ..forms import CustomUserCreationForm
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
