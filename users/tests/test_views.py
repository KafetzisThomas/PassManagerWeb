import pyotp
from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth import SESSION_KEY
from vault.models import Item

User = get_user_model()

class RegisterViewTests(TestCase):

    def setUp(self):
        self.valid_user_data = {
            "email": "user@test.com",
            "username": "user",
            "password1": "Str0ng_p@ssword",
            "password2": "Str0ng_p@ssword"
        }
        self.url = reverse("users:register")

    @patch("users.views.send_discord_signup_alert")
    def test_register_view_valid(self, mock_discord_alert):
        response = self.client.post(self.url, self.valid_user_data)
        self.assertRedirects(response, reverse("users:login"))

        user = User.objects.get(email="user@test.com")
        self.assertFalse(user.is_active)

        mock_discord_alert.assert_called_once_with(user)


class CustomLoginViewTests(TestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(
            email="user1@test.com",
            username="user1",
            password="Str0ng_p@ssword",
            enable_2fa=True
        )
        self.user2 = User.objects.create_user(
            email="user2@test.com",
            username="user2",
            password="Str0ng_p@ssword",
            enable_2fa=False
        )
        self.url = reverse("users:login")

    def test_login_with_2fa_enabled(self):
        form_data = {
            "username": "user1@test.com",
            "password": "Str0ng_p@ssword"
        }
        response = self.client.post(self.url, form_data)
        self.assertRedirects(response, reverse("users:2fa_verification"))
        self.assertEqual(self.client.session.get("user_id"), self.user1.id)
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_login_with_2fa_disabled(self):
        form_data = {
            "username": "user2@test.com",
            "password": "Str0ng_p@ssword"
        }
        self.client.post(self.url, form_data)
        self.assertIn(SESSION_KEY, self.client.session)
        self.assertEqual(int(self.client.session[SESSION_KEY]), self.user2.id)
        self.assertNotIn("user_id", self.client.session)


class TwoFactorVerificationViewTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@test.com", password="Str0ng_p@ssword", username="user", otp_secret=pyotp.random_base32()
        )
        self.two_factor_verification_url = reverse("users:2fa_verification")

        session = self.client.session
        session["user_id"] = self.user.id
        session.save()

    def test_valid_otp_submission(self):
        valid_otp = pyotp.TOTP(self.user.otp_secret).now()
        response = self.client.post(self.two_factor_verification_url, {"otp": valid_otp})
        self.assertRedirects(response, reverse("vault:vault"))
        self.assertIn(SESSION_KEY, self.client.session)  # user should be logged in
        self.assertNotIn("user_id", self.client.session)  # temp key cleaned up

    def test_invalid_otp_submission(self):
        self.client.post(self.two_factor_verification_url, {"otp": "123456"})
        self.assertNotIn(SESSION_KEY, self.client.session)  # user should not be logged in
        self.assertIn("user_id", self.client.session)  # temp key still in session


class AccountViewTests(TestCase):

    def setUp(self):
        self.url = reverse("users:account")
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_update_email_action(self):
        response = self.client.post(self.url, {"action": "update_email", "email": "new@test.com"})
        self.assertRedirects(response, self.url)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "new@test.com")

    def test_toggle_2fa_on(self):
        response = self.client.post(self.url, {"action": "toggle_2fa", "enable_2fa": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["show_2fa_modal"])
        self.assertIsNotNone(response.context["qr_code"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.otp_secret)
        self.assertFalse(self.user.enable_2fa)

    def test_confirm_2fa_success(self):
        self.user.otp_secret = pyotp.random_base32()
        self.user.save()

        valid_otp = pyotp.TOTP(self.user.otp_secret).now()
        response = self.client.post(self.url, {"action": "confirm_2fa", "otp": valid_otp})
        self.assertRedirects(response, self.url)

        self.user.refresh_from_db()
        self.assertTrue(self.user.enable_2fa)

    def test_confirm_2fa_failure_resets_secret(self):
        self.user.otp_secret = pyotp.random_base32()
        self.user.save()

        response = self.client.post(self.url, {"action": "confirm_2fa", "otp": "123456"})
        self.assertRedirects(response, self.url)

        self.user.refresh_from_db()
        self.assertFalse(self.user.enable_2fa)
        self.assertEqual(self.user.otp_secret, "")

    def test_toggle_2fa_off_clears_secrets(self):
        self.user.enable_2fa = True
        self.user.otp_secret = pyotp.random_base32()
        self.user.save()

        response = self.client.post(self.url, {"action": "toggle_2fa"})
        self.assertRedirects(response, self.url)

        self.user.refresh_from_db()
        self.assertFalse(self.user.enable_2fa)
        self.assertEqual(self.user.otp_secret, "")

class UpdateMasterPasswordViewTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="user@test.com", username="user", password="Str0ng_p@ssword"
        )
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")
        self.form_data = {
            "old_password": "Str0ng_p@ssword", "new_password1": "New_Str0ng_p@ssword", "new_password2": "New_Str0ng_p@ssword"
        }
        self.url = reverse("users:update_master_password")

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_update_master_password_without_items_succeeds(self):
        response = self.client.post(self.url, self.form_data)
        self.assertRedirects(response, reverse("vault:vault"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("New_Str0ng_p@ssword"))

    def test_update_master_password_reencrypts_vault_items(self):
        item = Item(name="Test Item", username="test", password="testpassword", notes="Test notes", owner=self.user)
        item.encrypt_sensitive_fields()
        item.save()

        old_encrypted_password = item.password

        response = self.client.post(self.url, self.form_data)
        self.assertRedirects(response, reverse("vault:vault"))

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("New_Str0ng_p@ssword"))

        item.refresh_from_db()
        self.assertNotEqual(item.password, old_encrypted_password)
