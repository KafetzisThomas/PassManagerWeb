"""
This module contains test cases for the following views:
* home, vault, new_item
"""

import os
import base64
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from unittest.mock import patch
from django.urls import reverse

from users.models import CustomUser
from ..models import Item
from ..forms import ItemForm
from ..utils import decrypt


class HomeViewTest(TestCase):
    """
    Test case for the home view.
    """

    def test_home_view_status_code(self):
        """
        Test if the home view returns a status code 200.
        """
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)

    def test_home_view_template_used(self):
        """
        Test if the home view uses the correct template.
        """
        response = self.client.get(reverse("home"))
        self.assertTemplateUsed(response, "passmanager/home.html")


class VaultViewTest(TestCase):
    """
    Test case for the vault view.
    """

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="12345", username="testuser"
        )
        self.user2 = CustomUser.objects.create_user(
            email="otheruser@example.com", password="54321", username="otheruser"
        )

        self.client.login(email="testuser@example.com", password="12345")

        # Create test items for both users
        for i in range(5):
            Item.objects.create(
                owner=self.user, name=f"Item {i}", date_added=f"2023-01-0{i+1}"
            )
            Item.objects.create(
                owner=self.user2, name=f"Other Item {i}", date_added=f"2023-01-0{i+1}"
            )

    def test_vault_view_redirect_if_not_logged_in(self):
        """
        Test if the vault view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("vault"))
        self.assertRedirects(response, "/user/login/?next=/vault/")

    def test_vault_view_status_code(self):
        """
        Test if the vault view returns a status code 200 for logged-in users.
        """
        response = self.client.get(reverse("vault"))
        self.assertEqual(response.status_code, 200)

    def test_vault_view_template_used(self):
        """
        Test if the vault view uses the correct template.
        """
        response = self.client.get(reverse("vault"))
        self.assertTemplateUsed(response, "passmanager/vault.html")

    def test_vault_view_items_for_logged_in_user(self):
        """
        Test if the vault view returns items only for the logged-in user.
        """
        response = self.client.get(reverse("vault"))
        page_obj = response.context["page_obj"]
        items = page_obj.object_list
        for item in items:
            self.assertEqual(item.owner, self.user)

    def test_vault_view_pagination(self):
        """
        Test if the vault view paginates items correctly.
        """
        response = self.client.get(reverse("vault"))
        page_obj = response.context["page_obj"]
        self.assertTrue(page_obj.has_next())
        self.assertEqual(len(page_obj), 3)

        response = self.client.get(reverse("vault") + "?page=2")
        page_obj = response.context["page_obj"]
        self.assertFalse(page_obj.has_next())
        self.assertEqual(len(page_obj), 2)


class NewItemViewTest(TestCase):
    """
    Test case for the new_item view.
    """

    @override_settings(ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)))
    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="12345", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="12345")

    def test_new_item_view_redirect_if_not_logged_in(self):
        """
        Test if the new_item view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("new_item"))
        self.assertRedirects(response, "/user/login/?next=/new_item/")

    def test_new_item_view_status_code_and_template(self):
        """
        Test if the new_item view returns a status code 200 and uses the correct template for logged-in users.
        """
        response = self.client.get(reverse("new_item"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/new_item.html")
        self.assertIsInstance(response.context["form"], ItemForm)

    def test_new_item_view_post_save_action(self):
        """
        Test if the new_item view correctly saves an item and redirects to the vault.
        """
        data = {
            "name": "Test Item",
            "website": "http://example.com",
            "username": "testuser",
            "password": "password123",
            "notes": "Test notes",
            "action": "save",
        }
        response = self.client.post(reverse("new_item"), data)
        self.assertRedirects(response, reverse("vault"))

        item = Item.objects.get(name="Test Item")
        self.assertEqual(item.owner, self.user)

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(str(messages[0]), "Item created successfully.")

    @patch("passmanager.views.generate_password")
    def test_new_item_view_post_generate_password_action(self, mock_generate_password):
        """
        Test if the new_item view correctly generates a password and updates the form.
        """
        mock_generate_password.return_value = "generatedpassword123"
        data = {
            "name": "Test Item",
            "website": "http://example.com",
            "username": "testuser",
            "password": "",
            "notes": "Test notes",
            "action": "generate_password",
        }
        response = self.client.post(reverse("new_item"), data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/new_item.html")
        self.assertEqual(
            response.context["form"].initial["password"], "generatedpassword123"
        )

    @patch("passmanager.views.check_password")
    def test_new_item_view_post_check_password_action(self, mock_check_password):
        """
        Test if the new_item view correctly checks if the password has been pwned and shows a message.
        """
        mock_check_password.return_value = 0
        data = {
            "name": "Test Item",
            "website": "http://example.com",
            "username": "testuser",
            "password": "safe_password",
            "notes": "Test notes",
            "action": "check_password",
        }
        response = self.client.post(reverse("new_item"), data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/new_item.html")

        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(
            str(messages[0]),
            "This password was not found in known data breaches. It must be safe to use.",
        )

    @override_settings(ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)))
    def test_new_item_view_post_save_action_with_encryption(self):
        """
        Test if the new_item view correctly encrypts data before saving.
        """
        data = {
            "name": "Encrypted Item",
            "website": "http://example.com",
            "username": "encrypteduser",
            "password": "encryptedpassword",
            "notes": "Encrypted notes",
            "action": "save",
        }
        response = self.client.post(reverse("new_item"), data)
        self.assertRedirects(response, reverse("vault"))
        encryption_key = os.getenv("ENCRYPTION_KEY").encode()

        item = Item.objects.get(name="Encrypted Item")
        self.assertNotEqual(item.website, "http://example.com")
        self.assertNotEqual(item.username, "encrypteduser")
        self.assertNotEqual(item.password, "encryptedpassword")
        self.assertNotEqual(item.notes, "Encrypted notes")

        decrypted_website = decrypt(item.website.encode(), encryption_key).decode(
            "utf-8"
        )
        decrypted_username = decrypt(item.username.encode(), encryption_key).decode(
            "utf-8"
        )
        decrypted_password = decrypt(item.password.encode(), encryption_key).decode(
            "utf-8"
        )
        decrypted_notes = decrypt(item.notes.encode(), encryption_key).decode("utf-8")

        self.assertEqual(decrypted_website, "http://example.com")
        self.assertEqual(decrypted_username, "encrypteduser")
        self.assertEqual(decrypted_password, "encryptedpassword")
        self.assertEqual(decrypted_notes, "Encrypted notes")
