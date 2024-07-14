"""
This module contains test cases for the following classes:
* CustomUserCreationForm (validation, required fields, and the save method)
* CustomAuthenticationForm (validation and authentication logic)
* CustomUserChangeForm (validation and saving functionality)
"""

from django.test import TestCase
from unittest.mock import MagicMock, patch
from django import forms
import pyotp

from ..models import CustomUser
from ..forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    CustomUserChangeForm,
)


@patch("turnstile.fields.TurnstileField.validate", return_value=True)
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
            "captcha_verification": "testsecret",
        }

        self.invalid_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "SecRet_p@ssword",
            "password2": "SecRetp@ssword",
            "captcha_verification": "testsecret",
        }

    def test_form_valid_data(self, mock: MagicMock):
        """
        Test that the form is valid when all required fields are provided and passwords match.
        """
        form = CustomUserCreationForm(data=self.valid_data)
        self.assertTrue(form.is_valid(), form.errors.as_json())

    def test_form_invalid_data(self, mock: MagicMock):
        """
        Test that the form is invalid when passwords do not match.
        """
        form = CustomUserCreationForm(data=self.invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password2", form.errors)

    def test_form_missing_email(self, mock: MagicMock):
        """
        Test that the form is invalid when the email is missing.
        """
        data = self.valid_data.copy()
        data.pop("email")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_form_missing_username(self, mock: MagicMock):
        """
        Test that the form is invalid when the username is missing.
        """
        data = self.valid_data.copy()
        data.pop("username")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_form_save(self, mock: MagicMock):
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


@patch("turnstile.fields.TurnstileField.validate", return_value=True)
class CustomAuthenticationFormTests(TestCase):
    """
    Test suite for the CustomAuthenticationForm.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.test_email = "testuser@example.com"
        self.test_password = "testpassword"
        self.test_otp_secret = "testotpsecret"
        self.test_otp = pyotp.TOTP(self.test_otp_secret).now()

        self.user = CustomUser.objects.create_user(
            email=self.test_email,
            password=self.test_password,
            otp_secret=self.test_otp_secret,
        )

    def test_form_valid_data(self, mock: MagicMock):
        """
        Test that the form is valid when correct email, OTP, and password are provided.
        """
        form_data = {
            "username": self.test_email,
            "password": self.test_password,
            "otp": self.test_otp,
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors.as_json())

    def test_form_invalid_email(self, mock: MagicMock):
        """
        Test that the form is invalid when an incorrect email is provided.
        """
        form_data = {
            "username": "wrongemail@example.com",
            "password": self.test_password,
            "otp": self.test_otp,
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("__all__", form.errors)
        self.assertEqual(
            form.errors["__all__"][0],
            "Please enter a correct email address and password. Note that both fields may be case-sensitive.",
        )

    def test_form_invalid_otp(self, mock: MagicMock):
        """
        Test that the form is invalid when an incorrect OTP is provided.
        """
        form_data = {
            "username": self.test_email,
            "password": self.test_password,
            "otp": "654321",  # Wrong OTP
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("__all__", form.errors)
        self.assertEqual(form.errors["__all__"][0], "Invalid OTP")

    def test_form_missing_email(self, mock: MagicMock):
        """
        Test that the form is invalid when the email is missing.
        """
        form_data = {
            "username": "",
            "password": self.test_password,
            "otp": self.test_otp,
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_form_missing_password(self, mock: MagicMock):
        """
        Test that the form is invalid when the password is missing.
        """
        form_data = {"username": self.test_email, "password": "", "otp": self.test_otp}
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)

    def test_form_clean_method_invalid_otp(self, mock: MagicMock):
        """
        Test the clean method of the form with invalid OTP.
        """
        form_data = {
            "username": self.test_email,
            "password": self.test_password,
            "otp": "654321",  # Wrong OTP
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid())
        with self.assertRaises(forms.ValidationError):
            form.clean()


class CustomUserChangeFormTests(TestCase):
    """
    Test suite for the CustomUserChangeForm.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.test_email = "testuser@example.com"
        self.test_username = "testuser"
        self.test_password = "testpassword"

        self.user = CustomUser.objects.create_user(
            email=self.test_email,
            username=self.test_username,
            password=self.test_password,
        )

    def test_form_valid_data(self):
        """
        Test that the form is valid when correct data is provided.
        """
        form_data = {
            "email": "updated@example.com",
            "username": "updated_username",
            "password1": "newpassword123",
            "password2": "newpassword123",
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertTrue(form.is_valid(), form.errors.as_json())

    def test_form_invalid_passwords_not_matching(self):
        """
        Test that the form is invalid when passwords do not match.
        """
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
            "password1": "newpassword123",
            "password2": "differentpassword",
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password2", form.errors)
        self.assertEqual(form.errors["password2"][0], "Passwords do not match.")

    def test_form_invalid_password_not_meeting_requirements(self):
        """
        Test that the form is invalid when the new password does not meet validation requirements.
        """
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
            "password1": "weak",
            "password2": "weak",
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password1", form.errors)

    def test_form_save(self):
        """
        Test that the form's save method updates the user's password correctly.
        """
        new_password = "newpassword123"
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
            "password1": new_password,
            "password2": new_password,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertTrue(form.is_valid())
        updated_user = form.save()
        self.assertTrue(updated_user.check_password(new_password))

    def test_form_save_no_password_change(self):
        """
        Test that the form's save method does not change the password if no new password is provided.
        """
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertTrue(form.is_valid())
        updated_user = form.save()
        self.assertTrue(updated_user.check_password(self.test_password))
