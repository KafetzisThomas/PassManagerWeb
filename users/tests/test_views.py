import pyotp
from django.test import TestCase, Client
from unittest.mock import MagicMock, patch
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth import SESSION_KEY
from passmanager.models import Item
from ..models import CustomUser
from ..forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    CustomUserChangeForm,
    MasterPasswordChangeForm,
)


@patch("turnstile.fields.TurnstileField.validate", return_value=True)
class RegisterViewTest(TestCase):
    """
    Test case for the register view.
    """

    def setUp(self):
        self.user_model = get_user_model()
        self.form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "testpassword123",
            "password2": "testpassword123",
            "captcha_verification": "testsecret",
        }

    def test_register_view_status_code_and_template(self, mock: MagicMock):
        """
        Test if the register view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:register"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/register.html")
        self.assertIsInstance(response.context["form"], CustomUserCreationForm)

    def test_register_view_valid(self, mock: MagicMock):
        """
        Test registering a new user with valid data.
        """
        response = self.client.post(reverse("users:register"), self.form_data)
        self.assertRedirects(response, reverse("users:login"))

        # Check if the user is created in the database
        self.assertTrue(
            self.user_model.objects.filter(email=self.form_data["email"]).exists()
        )

        # Check if the user is still logged out
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_register_view_post_invalid(self, mock: MagicMock):
        """
        Test registering a new user with invalid data.
        """
        self.form_data["password2"] = "wrongpassword"
        self.client.post(reverse("users:register"), self.form_data)

        # Check that user is not created in the database
        self.assertFalse(
            self.user_model.objects.filter(email="testuser@example.com").exists()
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
            "session_timeout": 300,
            "enable_2fa": True,
            "action": "save",
        }
        response = self.client.post(self.account_url, form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if user details are updated
        updated_user = CustomUser.objects.get(email="updateduser@example.com")
        self.assertEqual(updated_user.username, "updateduser")
        self.assertEqual(updated_user.session_timeout, 300)
        self.assertTrue(updated_user.enable_2fa)

        # Check that the OTP secret is generated & saved
        self.assertIsNotNone(updated_user.otp_secret)
        self.assertIsInstance(updated_user.otp_secret, str)

    def test_account_view_post_invalid_email(self):
        """
        Test updating account credentials with an invalid email.
        """
        form_data = {
            "email": "invalid-email",
            "username": "updateduser",
            "action": "save",
        }
        response = self.client.post(self.account_url, form_data)
        self.assertEqual(response.status_code, 200)

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


class UpdateMasterPasswordViewTest(TestCase):
    """
    Test case for the update_master_password view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="oldpassword", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="oldpassword")
        self.update_master_password_url = reverse("users:update_master_password")

        # Some items to test encryption
        self.items = []
        for _ in range(3):
            item = Item(
                owner=self.user,
                username="testuser",
                password="testpassword",
                notes="Test notes",
            )
            item.encrypt_sensitive_fields()
            item.save()

            # Add item to the list
            self.items.append(item)

    def test_update_master_password_view_get(self):
        """
        Test rendering the update_master_password page with GET request.
        """
        response = self.client.get(self.update_master_password_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/update_master_password.html")
        self.assertIsInstance(response.context["form"], MasterPasswordChangeForm)

    def test_update_master_password_view_post_valid_form(self):
        """
        Test updating master password with valid form data.
        """
        form_data = {
            "old_password": "oldpassword",
            "new_password1": "newpassword123",
            "new_password2": "newpassword123",
        }
        response = self.client.post(self.update_master_password_url, form_data)

        # Re-login after password update (simulating what happens after real password change)
        self.client.login(email="testuser@example.com", password="newpassword123")
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if the user's password is updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("newpassword123"))

        # Verify items are re-encrypted
        for item in self.items:
            self.assertNotEqual(item.username, "testuser")
            self.assertNotEqual(item.password, "testpassword")
            self.assertNotEqual(item.notes, "Test notes")

    def test_update_master_password_view_post_invalid_form(self):
        """
        Test updating master password with invalid form data.
        """
        form_data = {
            "old_password": "oldpassword",
            "new_password1": "newpassword123",
            "new_password2": "wrongpassword",
        }
        response = self.client.post(self.update_master_password_url, form_data)
        self.assertEqual(response.status_code, 200)

        # Ensure user's password remains unchanged
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("oldpassword"))


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


class CustomLoginViewTests(TestCase):
    """
    Test case for the CustomLogin view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.login_url = reverse("users:login")

    def test_login_view_get(self):
        """
        Test that the login view returns the login form on GET request.
        """
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertIsInstance(response.context["form"], CustomAuthenticationForm)

    def test_login_view_post_valid_credentials(self):
        """
        Test logging in with valid credentials.
        """
        form_data = {
            "username": "testuser@example.com",
            "password": "password",
        }
        response = self.client.post(self.login_url, form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if the user is logged in
        self.assertIn(SESSION_KEY, self.client.session)

    def test_login_view_post_invalid_credentials(self):
        """
        Test logging in with invalid credentials.
        """
        form_data = {
            "username": "testuser@example.com",
            "password": "wrongpassword",
        }
        response = self.client.post(self.login_url, form_data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/login.html")

        # Check if the user is not logged in
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_login_view_post_with_2fa_enabled(self):
        """
        Test logging in with 2FA enabled.
        """
        self.user.otp_secret = "test_otp_secret"
        self.user.save()

        form_data = {
            "username": "testuser@example.com",
            "password": "password",
        }
        response = self.client.post(self.login_url, form_data)
        self.assertRedirects(response, reverse("users:2fa_verification"))

        # Check if the user is not fully logged in yet
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session["user_id"], self.user.id)


class TwoFactorVerificationViewTests(TestCase):
    """
    Test case for the TwoFactorVerification view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com",
            password="password123",
            username="testuser",
            otp_secret=pyotp.random_base32(),
        )
        self.verification_url = reverse("users:2fa_verification")

        # Store user_id in session
        session = self.client.session
        session["user_id"] = self.user.id
        session.save()

    def test_get_verification_page(self):
        """
        Test that the verification page loads correctly.
        """
        response = self.client.get(self.verification_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/2fa_verification.html")

    def test_valid_otp_submission(self):
        """
        Test successful 2FA verification with valid OTP.
        """
        valid_otp = pyotp.TOTP(self.user.otp_secret).now()
        response = self.client.post(self.verification_url, {"otp": valid_otp})
        self.assertRedirects(response, reverse("passmanager:vault"))

        # User should be logged in
        self.assertIn(SESSION_KEY, self.client.session)

        # user_id should be removed from session
        self.assertNotIn("user_id", self.client.session)

    def test_invalid_otp_submission(self):
        """
        Test failed 2FA verification with invalid OTP.
        """
        response = self.client.post(self.verification_url, {"otp": "123456"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/2fa_verification.html")

        # User should not be logged in
        self.assertNotIn(SESSION_KEY, self.client.session)

        # user_id should still be in session
        self.assertIn("user_id", self.client.session)
