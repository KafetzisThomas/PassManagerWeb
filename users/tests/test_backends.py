from django.test import TestCase
from django.contrib.auth.backends import ModelBackend

from ..models import CustomUser


class EmailBackendTest(TestCase):
    """
    Test case for the EmailBackend class.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.backend = ModelBackend()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )

    def test_authenticate_with_valid_credentials(self):
        """
        Test authenticating with valid email and password.
        """
        user = self.backend.authenticate(
            None, username="testuser@example.com", password="password"
        )
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "testuser@example.com")

    def test_authenticate_with_invalid_password(self):
        """
        Test authenticating with invalid password.
        """
        user = self.backend.authenticate(
            None, username="testuser@example.com", password="wrongpassword"
        )
        self.assertIsNone(user)

    def test_authenticate_with_invalid_username(self):
        """
        Test authenticating with invalid email (username).
        """
        user = self.backend.authenticate(
            None, username="wronguser@example.com", password="password"
        )
        self.assertIsNone(user)

    def test_authenticate_user_does_not_exist(self):
        """
        Test authenticating when the user does not exist.
        """
        user = self.backend.authenticate(
            None, username="nonexistent@example.com", password="password"
        )
        self.assertIsNone(user)

    def test_authenticate_empty_credentials(self):
        """
        Test authenticating with empty email and password.
        """
        user = self.backend.authenticate(None, username="", password="")
        self.assertIsNone(user)

    def test_authenticate_empty_password(self):
        """
        Test authenticating with valid email and empty password.
        """
        user = self.backend.authenticate(
            None, username="testuser@example.com", password=""
        )
        self.assertIsNone(user)

    def test_authenticate_empty_username(self):
        """
        Test authenticating with empty email and valid password.
        """
        user = self.backend.authenticate(None, username="", password="password")
        self.assertIsNone(user)

    def test_authenticate_empty_username_and_password(self):
        """
        Test authenticating with empty email and password.
        """
        user = self.backend.authenticate(None, username="", password="")
        self.assertIsNone(user)
