"""
This module contains test cases for the following views:
* home, vault, new_item, edit_item, delete_item, password_generator
"""

import os
import base64
from django.test import TestCase, Client, override_settings
from django.contrib.messages import get_messages
from unittest.mock import patch
from django.urls import reverse

from users.models import CustomUser
from ..models import Item
from ..forms import ItemForm, PasswordGeneratorForm
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


class FaqViewTest(TestCase):
    """
    Test case for the faq view.
    """

    def test_faq_view_status_code(self):
        """
        Test if the faq view returns a status code 200.
        """
        response = self.client.get(reverse("faq"))
        self.assertEqual(response.status_code, 200)

    def test_faq_view_template_used(self):
        """
        Test if the faq view uses the correct template.
        """
        response = self.client.get(reverse("faq"))
        self.assertTemplateUsed(response, "passmanager/faq.html")


class VaultViewTest(TestCase):
    """
    Test case for the vault view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@gmail.com", password="12345", username="testuser"
        )
        self.user2 = CustomUser.objects.create_user(
            email="otheruser@gmail.com", password="54321", username="otheruser"
        )

        self.client.login(email="testuser@gmail.com", password="12345")

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

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@gmail.com", password="12345", username="testuser"
        )
        self.client.login(email="testuser@gmail.com", password="12345")

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


class EditItemViewTest(TestCase):
    """
    Test case for the edit_item view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@gmail.com", password="password", username="testuser"
        )
        self.other_user = CustomUser.objects.create_user(
            email="otheruser@gmail.com", password="password", username="otheruser"
        )
        self.client.login(email="testuser@gmail.com", password="password")
        self.item = Item.objects.create(
            name="Test Item",
            website="http://example.com",
            username="testuser",
            password="testpassword",
            notes="Test notes",
            owner=self.user,
        )

    def test_edit_item_view_redirect_if_not_logged_in(self):
        """
        Test to verify that non-logged-in users are redirected to the login page when trying to access the edit_item view.
        """
        self.client.logout()
        response = self.client.get(
            reverse("edit_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(
            response, "/user/login/?next=/edit_item/{}/".format(self.item.id)
        )

    def test_edit_item_view_permission_denied_for_other_user(self):
        """
        Test to verify that other users cannot access the edit_item view of items they don't own.
        """
        self.client.login(email="otheruser@gmail.com", password="password")
        response = self.client.get(
            reverse("edit_item", kwargs={"item_id": self.item.id})
        )
        self.assertEqual(response.status_code, 404)

    def test_edit_item_view_post_save_action(self):
        """
        Verifies that an item's attributes are correctly updated after a save action.
        """
        data = {
            "name": "Modified Item",
            "website": "http://modified-example.com",
            "username": "modifieduser",
            "password": "modifiedpassword",
            "notes": "Modified notes",
            "action": "save",
        }
        response = self.client.post(
            reverse("edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("vault"))
        self.item.refresh_from_db()
        self.assertEqual(self.item.name, "Modified Item")

    @patch("passmanager.views.generate_password")
    def test_edit_item_view_post_generate_password_action(self, mock_generate_password):
        """
        Verifies that the generate_password action generates a new password.
        """
        mock_generate_password.return_value = "generatedpassword123"
        data = {
            "name": "Modified Item",
            "website": "http://modified-example.com",
            "username": "modifieduser",
            "password": "",
            "notes": "Modified notes",
            "action": "generate_password",
        }
        response = self.client.post(
            reverse("edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/edit_item.html")
        self.assertEqual(
            response.context["form"].initial["password"], "generatedpassword123"
        )

    def test_edit_item_view_post_check_password_action(self):
        """
        Verifies that the check_password action correctly processes the form data (password).
        """
        data = {
            "name": "Modified Item",
            "website": "http://modified-example.com",
            "username": "modifieduser",
            "password": "safe_password",
            "notes": "Modified notes",
            "action": "check_password",
        }
        response = self.client.post(
            reverse("edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/edit_item.html")

    def test_edit_item_view_post_delete_action(self):
        """
        Verifies that an item is correctly deleted when the delete action is triggered.
        """
        data = {
            "name": "Modified Item",
            "website": "http://modified-example.com",
            "username": "modifieduser",
            "password": "modifiedpassword",
            "notes": "Modified notes",
            "action": "delete",
        }
        response = self.client.post(
            reverse("edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)  # Ensure item is deleted

    @override_settings(ENCRYPTION_KEY=base64.urlsafe_b64encode(os.urandom(32)))
    def test_edit_item_view_post_save_action_with_encryption(self):
        """
        Verifies that item attributes are correctly encrypted and decrypted after a save action.
        """
        encryption_key = os.getenv("ENCRYPTION_KEY").encode()

        data = {
            "name": "Encrypted Item",
            "website": "http://example.com",
            "username": "encrypteduser",
            "password": "encryptedpassword",
            "notes": "Encrypted notes",
            "action": "save",
        }
        response = self.client.post(
            reverse("edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("vault"))

        self.item.refresh_from_db()
        decrypted_website = decrypt(self.item.website.encode(), encryption_key).decode(
            "utf-8"
        )
        decrypted_username = decrypt(
            self.item.username.encode(), encryption_key
        ).decode("utf-8")
        decrypted_password = decrypt(
            self.item.password.encode(), encryption_key
        ).decode("utf-8")
        decrypted_notes = decrypt(self.item.notes.encode(), encryption_key).decode(
            "utf-8"
        )

        self.assertEqual(decrypted_website, "http://example.com")
        self.assertEqual(decrypted_username, "encrypteduser")
        self.assertEqual(decrypted_password, "encryptedpassword")
        self.assertEqual(decrypted_notes, "Encrypted notes")


class DeleteItemViewTest(TestCase):
    """
    Test case for the delete_item view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@gmail.com", password="password", username="testuser"
        )
        self.other_user = CustomUser.objects.create_user(
            email="otheruser@gmail.com", password="password", username="otheruser"
        )
        self.client = Client()
        self.item = Item.objects.create(
            name="Test Item",
            website="http://example.com",
            username="testuser",
            password="testpassword",
            notes="Test notes",
            owner=self.user,
        )

    def test_delete_item_view_logged_in_owner(self):
        """
        Test that an owner can successfully delete their own item.
        """
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("delete_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(response, reverse("vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)  # Ensure item is deleted

    def test_delete_item_view_not_logged_in(self):
        """
        Test that a not logged-in user is redirected to the login page.
        """
        response = self.client.post(
            reverse("delete_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(
            response, "/user/login/?next=/edit_item/{}/delete".format(self.item.id)
        )


class PasswordGeneratorViewTest(TestCase):
    """
    Test case for the password_generator view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()

    def test_password_generator_view_get(self):
        """
        Test GET request to password_generator view returns form.
        """
        response = self.client.get(reverse("password_generator"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)
        self.assertEqual(
            response.context["password"], ""
        )  # Ensure password is empty initially

    @patch("passmanager.views.generate_password")
    def test_password_generator_view_post(self, mock_generate_password):
        """
        Test POST request to password_generator view generates password.
        """
        mock_generate_password.return_value = "GeneratedPassword123"
        data = {
            "length": 12,
            "letters": True,
            "digits": True,
            "special_chars": False,
        }

        response = self.client.post(reverse("password_generator"), data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertEqual(response.context["password"], "GeneratedPassword123")

        mock_generate_password.assert_called_once_with(12, True, True, False)

    def test_password_generator_view_post_invalid_form(self):
        """
        Test POST request with invalid data returns form with errors.
        """
        data = {
            "length": 4,  # Invalid length (< min_value)
            "letters": True,
            "digits": True,
            "special_chars": False,
        }

        response = self.client.post(reverse("password_generator"), data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)
        self.assertIn("length", response.context["form"].errors)

    def test_password_generator_view_post_empty_data(self):
        """
        Test POST request with empty data returns form with initial values.
        """
        response = self.client.post(reverse("password_generator"), {})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)
        self.assertEqual(
            response.context["password"], ""
        )  # Ensure password remains empty
