"""
This module contains test cases for the CustomUserManager class.
The tests cover the creation of regular users and superusers,
as well as handling of missing email addresses and validation
of superuser fields.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from ..managers import CustomUserManager


class CustomUserManagerTests(TestCase):
    """
    Test suite for the CustomUserManager.
    """

    def setUp(self):
        """
        Set up the test environment by defining the user model and manager.
        """
        self.user_model = get_user_model()
        self.manager = CustomUserManager()
        self.manager.model = self.user_model
        self.user_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password": "password123",
        }

    def test_create_user(self):
        """
        Test that a regular user can be created with an email and password.
        """
        user = self.manager.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data["email"])
        self.assertTrue(user.check_password(self.user_data["password"]))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_user_without_email(self):
        """
        Test that creating a user without an email raises a ValueError.
        """
        with self.assertRaises(ValueError) as e:
            self.manager.create_user(email="", password="password123")
        self.assertEqual(str(e.exception), str(_("Users must have an email address")))

    def test_create_superuser(self):
        """
        Test that a superuser can be created with the appropriate flags.
        """
        superuser_data = self.user_data.copy()
        superuser_data["email"] = "admin@example.com"
        superuser = self.manager.create_superuser(**superuser_data)
        self.assertEqual(superuser.email, superuser_data["email"])
        self.assertTrue(superuser.check_password(superuser_data["password"]))
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)

    def test_create_superuser_missing_is_staff(self):
        """
        Test that creating a superuser without is_staff=True raises a ValueError.
        """
        superuser_data = self.user_data.copy()
        superuser_data["email"] = "admin@example.com"
        superuser_data["is_staff"] = False
        with self.assertRaises(ValueError) as e:
            self.manager.create_superuser(**superuser_data)
        self.assertEqual(str(e.exception), str(_("Superuser must have is_staff=True.")))

    def test_create_superuser_missing_is_superuser(self):
        """
        Test that creating a superuser without is_superuser=True raises a ValueError.
        """
        superuser_data = self.user_data.copy()
        superuser_data["email"] = "admin@example.com"
        superuser_data["is_superuser"] = False
        with self.assertRaises(ValueError) as e:
            self.manager.create_superuser(**superuser_data)
        self.assertEqual(
            str(e.exception), str(_("Superuser must have is_superuser=True."))
        )
