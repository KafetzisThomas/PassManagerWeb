"""
This module contains test cases for the CustomUserCreationForm class.
The tests cover form validation, required fields, and the save method.
"""

from django.test import TestCase
from ..models import CustomUser
from ..forms import CustomUserCreationForm


class CustomUserCreationFormTests(TestCase):
    """
    Test suite for the CustomUserCreationForm.
    """

    def setUp(self):
        """
        Set up the test environment by defining valid and invalid form data.
        """
        self.valid_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "SecRet_p@ssword",
            "password2": "SecRet_p@ssword",
        }

        self.invalid_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "SecRet_p@ssword",
            "password2": "SecRetp@ssword",
        }

    def test_form_valid_data(self):
        """
        Test that the form is valid when all required fields are provided and passwords match.
        """
        form = CustomUserCreationForm(data=self.valid_data)
        self.assertTrue(form.is_valid(), form.errors.as_json())

    def test_form_invalid_data(self):
        """
        Test that the form is invalid when passwords do not match.
        """
        form = CustomUserCreationForm(data=self.invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password2", form.errors)

    def test_form_missing_email(self):
        """
        Test that the form is invalid when the email is missing.
        """
        data = self.valid_data.copy()
        data.pop("email")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_form_missing_username(self):
        """
        Test that the form is invalid when the username is missing.
        """
        data = self.valid_data.copy()
        data.pop("username")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_form_save(self):
        """
        Test that the form's save method works correctly.
        """
        form = CustomUserCreationForm(data=self.valid_data)
        self.assertTrue(form.is_valid(), form.errors.as_json())
        user = form.save()
        self.assertIsInstance(user, CustomUser)
        self.assertEqual(user.email, self.valid_data["email"])
        self.assertEqual(user.username, self.valid_data["username"])
        self.assertTrue(user.check_password(self.valid_data["password1"]))
