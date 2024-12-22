"""
This module contains test cases for the CustomUser model.
The tests cover various aspects of the model, including user creation,
unique email constraint, otp_secret field validation, custom user manager,
and the __str__ method.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError


class CustomUserModelTests(TestCase):
    """
    Test suite for the CustomUser model.
    """

    def setUp(self):
        """
        Set up the test environment by defining the user model and user data.
        """
        self.user_model = get_user_model()
        self.user_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password": "password123",
            "otp_secret": "12345678901234567890123456789012",
            "session_timeout": 300,
        }

    def test_create_user(self):
        """
        Test that a user can be created with the given data.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data["email"])
        self.assertEqual(user.username, self.user_data["username"])
        self.assertTrue(user.check_password(self.user_data["password"]))
        self.assertEqual(user.otp_secret, self.user_data["otp_secret"])
        self.assertEqual(user.session_timeout, self.user_data["session_timeout"])

    def test_create_superuser(self):
        """
        Test that a superuser can be created and has the correct flags.
        """
        superuser_data = self.user_data.copy()
        superuser_data["email"] = "admin@example.com"
        superuser = self.user_model.objects.create_superuser(**superuser_data)
        self.assertEqual(superuser.email, superuser_data["email"])
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)

    def test_email_unique(self):
        """
        Test that the email field is unique by attempting to create two users with the same email.
        """
        self.user_model.objects.create_user(**self.user_data)
        with self.assertRaises(IntegrityError):
            self.user_model.objects.create_user(**self.user_data)

    def test_otp_secret_field(self):
        """
        Test that the otp_secret field is correctly set and has the appropriate length.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(user.otp_secret, self.user_data["otp_secret"])
        self.assertEqual(len(user.otp_secret), 32)

    def test_custom_user_manager(self):
        """
        Test that the custom user manager creates a user instance of the correct type.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertIsInstance(user, self.user_model)

    def test_str_method(self):
        """
        Test that the __str__ method returns the user's email.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(str(user), user.email)
