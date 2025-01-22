import pyotp
from django.test import TestCase
from unittest.mock import MagicMock, patch
from ..models import CustomUser
from ..forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    TwoFactorVerificationForm,
    CustomUserChangeForm,
    MasterPasswordChangeForm,
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
        Test that the form is valid when all fields are provided and passwords match.
        """
        form = CustomUserCreationForm(data=self.valid_data)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_invalid_data(self, mock: MagicMock):
        """
        Test that the form is invalid when passwords do not match.
        """
        form = CustomUserCreationForm(data=self.invalid_data)
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_missing_email(self, mock: MagicMock):
        """
        Test that the form is invalid when the email is missing.
        """
        data = self.valid_data.copy()
        data.pop("email")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_missing_username(self, mock: MagicMock):
        """
        Test that the form is invalid when the username is missing.
        """
        data = self.valid_data.copy()
        data.pop("username")
        form = CustomUserCreationForm(data=data)
        self.assertFalse(form.is_valid(), form.errors)


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

        self.user = CustomUser.objects.create_user(
            email=self.test_email,
            password=self.test_password,
        )

    def test_form_valid_data(self):
        """
        Test that the form is valid when correct email and password are provided.
        """
        form_data = {
            "username": self.test_email,
            "password": self.test_password,
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_invalid_email(self):
        """
        Test that the form is invalid when an incorrect email is provided.
        """
        form_data = {
            "username": "wrongemail@example.com",
            "password": self.test_password,
        }
        form = CustomAuthenticationForm(data=form_data)
        self.assertFalse(form.is_valid(), form.errors)


class TwoFactorVerificationFormTests(TestCase):
    """
    Test suite for the TwoFactorVerificationForm.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.test_username = "testuser"
        self.test_email = "testuser@example.com"
        self.test_password = "testpassword"
        self.test_otp_secret = pyotp.random_base32()

        self.user = CustomUser.objects.create_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            otp_secret=self.test_otp_secret,
        )

    def test_form_valid_with_correct_otp(self):
        """
        Test that the form is valid when provided with a correct OTP.
        """
        valid_otp = pyotp.TOTP(self.user.otp_secret).now()
        form = TwoFactorVerificationForm(data={"otp": valid_otp}, user=self.user)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_invalid_without_user(self):
        """
        Test that the form is invalid when no user is provided.
        """
        form = TwoFactorVerificationForm(data={"otp": self.test_otp_secret})
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_invalid_without_otp_secret(self):
        """
        Test that the form is invalid when the user lacks an OTP secret.
        """
        user_without_otp = CustomUser.objects.create_user(
            username="testuser2",
            email="testuser2@example.com",
            password=self.test_password,
        )
        form = TwoFactorVerificationForm(
            data={"otp": self.test_otp_secret}, user=user_without_otp
        )
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_invalid_with_wrong_otp(self):
        """
        Test that the form is invalid when an incorrect OTP is provided.
        """
        form = TwoFactorVerificationForm(
            data={"otp": self.test_otp_secret}, user=self.user
        )
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_invalid_with_empty_otp(self):
        """
        Test that the form is invalid when an empty OTP is provided.
        """
        form = TwoFactorVerificationForm(data={"otp": ""}, user=self.user)
        self.assertFalse(form.is_valid(), form.errors)


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
        self.session_timeout = 300
        self.enable_2fa = False

        self.user = CustomUser.objects.create_user(
            email=self.test_email,
            username=self.test_username,
            password=self.test_password,
            session_timeout=self.session_timeout,
            enable_2fa=self.enable_2fa,
        )

    def test_form_valid_data(self):
        """
        Test that the form is valid when correct data is provided.
        """
        form_data = {
            "email": "updated@example.com",
            "username": "updated_username",
            "session_timeout": 600,
            "enable_2fa": True,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_enable_2fa_toggle(self):
        """
        Test that the form correctly updates the enable_2fa field.
        """
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
            "session_timeout": self.session_timeout,
            "enable_2fa": True,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertTrue(form.is_valid(), form.errors)
        updated_user = form.save()
        self.assertTrue(updated_user.enable_2fa)

    def test_form_invalid_email(self):
        """
        Test that the form is invalid when an incorrect email is provided.
        """
        form_data = {
            "email": "invalid-email",
            "username": self.test_username,
            "session_timeout": self.session_timeout,
            "enable_2fa": self.enable_2fa,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_missing_username(self):
        """
        Test that the form is invalid when the username is missing.
        """
        form_data = {
            "email": self.test_email,
            "username": "",
            "session_timeout": self.session_timeout,
            "enable_2fa": self.enable_2fa,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_invalid_session_timeout(self):
        """
        Test that the form is invalid when an incorrect session timeout is provided.
        """
        form_data = {
            "email": self.test_email,
            "username": self.test_username,
            "session_timeout": "invalid_timeout",
            "enable_2fa": self.enable_2fa,
        }
        form = CustomUserChangeForm(instance=self.user, data=form_data)
        self.assertFalse(form.is_valid(), form.errors)


class MasterPasswordChangeFormTests(TestCase):
    """
    Test suite for the MasterPasswordChangeForm.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="oldpassword", username="testuser"
        )
        self.form_data_valid = {
            "old_password": "oldpassword",
            "new_password1": "newpassword123",
            "new_password2": "newpassword123",
        }
        self.form_data_invalid_old_password = {
            "old_password": "wrongpassword",
            "new_password1": "newpassword123",
            "new_password2": "newpassword123",
        }
        self.form_data_mismatch_passwords = {
            "old_password": "oldpassword",
            "new_password1": "newpassword123",
            "new_password2": "differentpassword",
        }

    def test_form_valid_data(self):
        """
        Test that the form is valid when all required fields are provided and passwords match.
        """
        form = MasterPasswordChangeForm(user=self.user, data=self.form_data_valid)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_invalid_old_password(self):
        """
        Test that the form is invalid when the old password is incorrect.
        """
        form = MasterPasswordChangeForm(
            user=self.user, data=self.form_data_invalid_old_password
        )
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_mismatch_passwords(self):
        """
        Test that the form is invalid when the new passwords do not match.
        """
        form = MasterPasswordChangeForm(
            user=self.user, data=self.form_data_mismatch_passwords
        )
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_missing_old_password(self):
        """
        Test that the form is invalid when the old password is missing.
        """
        data = self.form_data_valid.copy()
        data.pop("old_password")
        form = MasterPasswordChangeForm(user=self.user, data=data)
        self.assertFalse(form.is_valid(), form.errors)

    def test_form_missing_new_password_fields(self):
        """
        Test that the form is invalid when the new_password fields are missing.
        """
        data = self.form_data_valid.copy()
        data.pop("new_password1")
        data.pop("new_password2")
        form = MasterPasswordChangeForm(user=self.user, data=data)
        self.assertFalse(form.is_valid(), form.errors)
