import pyotp
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth import SESSION_KEY
from passmanager.models import Item
from ..forms import (
    CustomUserCreationForm,
    CustomAuthenticationForm,
    CustomUserChangeForm,
    MasterPasswordChangeForm,
    TwoFactorVerificationForm,
)


class RegisterViewTests(TestCase):
    """
    Test case for the register view.
    """

    def setUp(self):
        """
        Set up the test environment by defining valid data.
        """
        self.user_model = get_user_model()
        self.form_data = {
            "email": "testuser@example.com",
            "username": "testuser",
            "password1": "SecRet_p@ssword",
            "password2": "SecRet_p@ssword",
        }

    def test_register_view_status_code_and_template(self):
        """
        Test if the register view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:register"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/register.html")
        self.assertIsInstance(response.context["form"], CustomUserCreationForm)

    def test_register_view_valid(self):
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

    def test_register_view_post_invalid(self):
        """
        Test registering a new user with invalid data.
        """
        self.form_data["password2"] = "wrongpassword"
        self.client.post(reverse("users:register"), self.form_data)

        # Check that user is not created in the database
        self.assertFalse(
            self.user_model.objects.filter(email="testuser@example.com").exists()
        )


class AccountViewTests(TestCase):
    """
    Test case for the account view.
    """

    def setUp(self):
        """
        Set up the test environment by defining valid data and creating a test user.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", password="password123", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password123")

        self.form_data = {
            "email": "updateduser@example.com",
            "username": "updateduser",
            "session_timeout": 300,
            "enable_2fa": True,
            "action": "save",
        }

    def test_account_view_status_code_and_template(self):
        """
        Test if the account view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:account"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/account.html")
        self.assertIsInstance(response.context["form"], CustomUserChangeForm)

    def test_account_view_valid(self):
        """
        Test updating account credentials with valid data.
        """
        response = self.client.post(reverse("users:account"), self.form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if user credentials are updated
        updated_user = self.user_model.objects.get(email=self.form_data["email"])
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
        self.form_data["email"] = "invalid-email"
        self.client.post(reverse("users:account"), self.form_data)

        # Ensure user credentials remain unchanged
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "testuser@example.com")
        self.assertEqual(self.user.username, "testuser")

    def test_account_view_not_logged_in(self):
        """
        Test accessing view when not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("users:account"))
        self.assertRedirects(response, "/user/login/?next=/user/account/")


class UpdateMasterPasswordViewTests(TestCase):
    """
    Test case for the update_master_password view.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user, items and valid data.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", password="oldpassword", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="oldpassword")

        self.form_data = {
            "old_password": "oldpassword",
            "new_password1": "SecRet_p@ssword",
            "new_password2": "SecRet_p@ssword",
        }

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

    def test_update_master_password_view_status_code_and_template(self):
        """
        Test if view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:update_master_password"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/update_master_password.html")
        self.assertIsInstance(response.context["form"], MasterPasswordChangeForm)

    def test_update_master_password_view_valid_data(self):
        """
        Test updating master password with valid data.
        """
        response = self.client.post(
            reverse("users:update_master_password"), self.form_data
        )

        # Re-login after password update (simulating what happens after real password change)
        self.client.login(email="testuser@example.com", password="SecRet_p@ssword")
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if the user's password is updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("SecRet_p@ssword"))

        # Verify items are re-encrypted
        for item in self.items:
            self.assertNotEqual(item.username, "testuser")
            self.assertNotEqual(item.password, "testpassword")
            self.assertNotEqual(item.notes, "Test notes")

    def test_update_master_password_view_invalid_data(self):
        """
        Test updating master password with invalid data.
        """
        self.form_data["new_password2"] = "wrongpassword"
        self.client.post(reverse("users:update_master_password"), self.form_data)
        self.assertTrue(self.user.check_password("oldpassword"))


class DeleteAccountViewTests(TestCase):
    """
    Test case for the delete_account view.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", password="password123", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password123")

    def test_delete_account_view(self):
        """
        Test deleting the user account successfully.
        """
        response = self.client.post(reverse("users:delete_account"))
        self.assertRedirects(response, reverse("users:register"))

        # Check that the user is deleted
        self.assertFalse(self.user_model.objects.filter(id=self.user.id).exists())

    def test_delete_account_view_not_logged_in(self):
        """
        Test accessing the view when not logged in.
        """
        self.client.logout()
        response = self.client.post(reverse("users:delete_account"))
        self.assertRedirects(
            response, "/user/login/?next=/user/account/delete_account/"
        )

        # Ensure the user is not deleted
        self.assertTrue(self.user_model.objects.filter(id=self.user.id).exists())


class CustomLoginViewTests(TestCase):
    """
    Test case for the CustomLogin view.
    """

    def setUp(self):
        """
        Set up the test environment by defining data and creating a test user.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", password="password123", username="testuser"
        )
        self.form_data = {
            "username": "testuser@example.com",
            "password": "password123",
        }

    def test_custom_login_view_status_code_and_template(self):
        """
        Test if view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertIsInstance(response.context["form"], CustomAuthenticationForm)

    def test_login_view_valid_credentials(self):
        """
        Test logging in with valid credentials.
        """
        response = self.client.post(reverse("users:login"), self.form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        # Check if the user is logged in
        self.assertIn(SESSION_KEY, self.client.session)

    def test_login_view_post_with_2fa_enabled(self):
        """
        Test logging in with 2FA enabled.
        """
        self.user.otp_secret = "test_otp_secret"
        self.user.save()
        response = self.client.post(reverse("users:login"), self.form_data)
        self.assertRedirects(response, reverse("users:2fa_verification"))

        # Check if the user is not fully logged in yet
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertEqual(self.client.session["user_id"], self.user.id)

    def test_login_view_post_invalid_credentials(self):
        """
        Test logging in with invalid credentials.
        """
        self.form_data["password"] = "wrongpassword"
        self.client.post(reverse("users:login"), self.form_data)

        # Check if the user is not logged in
        self.assertNotIn(SESSION_KEY, self.client.session)


class TwoFactorVerificationViewTests(TestCase):
    """
    Test case for the TwoFactorVerification view.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com",
            password="password123",
            username="testuser",
            otp_secret=pyotp.random_base32(),
        )

        # Store user_id in session
        session = self.client.session
        session["user_id"] = self.user.id
        session.save()

    def test_two_factor_verification_view_status_code_and_template(self):
        """
        Test if view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("users:2fa_verification"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/2fa_verification.html")
        self.assertIsInstance(response.context["form"], TwoFactorVerificationForm)

    def test_valid_otp_submission(self):
        """
        Test successful 2FA verification with valid OTP.
        """
        valid_otp = pyotp.TOTP(self.user.otp_secret).now()
        response = self.client.post(
            reverse("users:2fa_verification"), {"otp": valid_otp}
        )
        self.assertRedirects(response, reverse("passmanager:vault"))

        # User should be logged in
        self.assertIn(SESSION_KEY, self.client.session)

        # user_id should be removed from session
        self.assertNotIn("user_id", self.client.session)

    def test_invalid_otp_submission(self):
        """
        Test failed 2FA verification with invalid OTP.
        """
        self.client.post(reverse("users:2fa_verification"), {"otp": "123456"})

        # User should not be logged in
        self.assertNotIn(SESSION_KEY, self.client.session)

        # user_id should still be in session
        self.assertIn("user_id", self.client.session)
