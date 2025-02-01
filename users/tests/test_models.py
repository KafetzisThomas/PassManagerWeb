from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError


class CustomUserModelTests(TestCase):
    """
    Test suite for the CustomUser model.
    """

    def setUp(self):
        """
        Set up the test environment by defining valid user data.
        """
        self.user_model = get_user_model()
        self.user_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password": "password123",
            "otp_secret": "12345678901234567890123456789012",
            "session_timeout": 300,
            "enable_2fa": False,
            "allow_account_update_notifications": True,
            "allow_master_password_update_notifications": True,
        }

    def test_valid_user_creation(self):
        """
        Test that a user can be created with the given data.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(user.email, self.user_data["email"])
        self.assertEqual(user.username, self.user_data["username"])
        self.assertTrue(user.check_password(self.user_data["password"]))
        self.assertEqual(user.otp_secret, self.user_data["otp_secret"])
        self.assertEqual(user.session_timeout, self.user_data["session_timeout"])
        self.assertEqual(user.enable_2fa, self.user_data["enable_2fa"])
        self.assertEqual(user.enable_2fa, self.user_data["enable_2fa"])
        self.assertEqual(user.enable_2fa, self.user_data["enable_2fa"])

    def test_email_unique(self):
        """
        Test that the email field is unique.
        """
        self.user_model.objects.create_user(**self.user_data)
        with self.assertRaises(IntegrityError):
            self.user_model.objects.create_user(**self.user_data)

    def test_otp_secret_field(self):
        """
        Test that the otp_secret field is correctly set.
        """
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(user.otp_secret, self.user_data["otp_secret"])
        self.assertEqual(len(user.otp_secret), 32)

    def test_salt_generation(self):
        """
        Test that salt is automatically generated if not provided.
        """
        data = self.user_data.copy()
        user = self.user_model.objects.create_user(**data)
        self.assertIsNotNone(user.encryption_salt)
