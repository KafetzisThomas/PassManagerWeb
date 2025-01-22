import os
import csv
import base64
from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.messages import get_messages
from django.contrib.auth import get_user_model
from unittest.mock import patch
from django.urls import reverse
from users.models import CustomUser
from ..models import Item
from ..forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm


class HomeViewTests(TestCase):
    """
    Test case for the home view.
    """

    def test_home_view_status_code(self):
        """
        Test if the home view returns a status code 200.
        """
        response = self.client.get(reverse("passmanager:home"))
        self.assertEqual(response.status_code, 200)

    def test_home_view_template_used(self):
        """
        Test if the home view uses the correct template.
        """
        response = self.client.get(reverse("passmanager:home"))
        self.assertTemplateUsed(response, "passmanager/home.html")


class FaqViewTests(TestCase):
    """
    Test case for the faq view.
    """

    def test_faq_view_status_code(self):
        """
        Test if the faq view returns a status code 200.
        """
        response = self.client.get(reverse("passmanager:faq"))
        self.assertEqual(response.status_code, 200)

    def test_faq_view_template_used(self):
        """
        Test if the faq view uses the correct template.
        """
        response = self.client.get(reverse("passmanager:faq"))
        self.assertTemplateUsed(response, "passmanager/faq.html")


class VaultViewTests(TestCase):
    """
    Test case for the vault view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", password="password123", username="testuser"
        )
        self.user2 = self.user_model.objects.create_user(
            email="otheruser@example.com", password="password456", username="otheruser"
        )
        self.client.login(email="testuser@example.com", password="password123")

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
        response = self.client.get(reverse("passmanager:vault"))
        self.assertRedirects(response, "/user/login/?next=/vault/")

    def test_new_item_view_status_code_and_template(self):
        """
        Test if the vault view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("passmanager:vault"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/vault.html")
        self.assertIsInstance(response.context["form"], ItemForm)

    def test_vault_view_items_for_logged_in_user(self):
        """
        Test if the vault view returns items only for the logged-in user.
        """
        response = self.client.get(reverse("passmanager:vault"))
        page_obj = response.context["page_obj"]
        items = page_obj.object_list
        for item in items:
            self.assertEqual(item.owner, self.user)

    def test_vault_view_pagination(self):
        """
        Test if the vault view paginates items correctly.
        """
        response = self.client.get(reverse("passmanager:vault"))
        page_obj = response.context["page_obj"]
        self.assertTrue(page_obj.has_next())
        self.assertEqual(len(page_obj), 4)

        response = self.client.get(reverse("passmanager:vault") + "?page=2")
        page_obj = response.context["page_obj"]
        self.assertFalse(page_obj.has_next())
        self.assertEqual(len(page_obj), 1)


class NewItemViewTests(TestCase):
    """
    Test case for the new_item view.
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

    def test_new_item_view_redirect_if_not_logged_in(self):
        """
        Test if the new_item view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("passmanager:new_item"))
        self.assertRedirects(response, "/user/login/?next=/new_item/")

    def test_new_item_view_status_code_and_template(self):
        """
        Test if the new_item view returns a status code 200 and uses the correct template for logged-in users.
        """
        response = self.client.get(reverse("passmanager:new_item"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/new_item.html")
        self.assertIsInstance(response.context["form"], ItemForm)

    def test_new_item_view_save_action(self):
        """
        Test if the new_item view correctly encrypts & saves item.
        """
        data = {
            "name": "Test Item",
            "username": "testuser",
            "password": "password123",
            "url": "http://example.com",
            "notes": "Test notes",
            "action": "save",
        }
        response = self.client.post(reverse("passmanager:new_item"), data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        item = Item.objects.get(name="Test Item")
        self.assertNotEqual(item.username, "testuser")
        self.assertNotEqual(item.password, "password123")
        self.assertNotEqual(item.notes, "Test notes")

        item.decrypt_sensitive_fields()
        self.assertEqual(item.name, "Test Item")
        self.assertEqual(item.username, "testuser")
        self.assertEqual(item.password, "password123")
        self.assertEqual(item.url, "http://example.com")
        self.assertEqual(item.notes, "Test notes")

    @patch("passmanager.views.generate_password")
    def test_new_item_view_post_generate_password_action(self, mock_generate_password):
        """
        Test if the new_item view correctly generates a password and updates the form.
        """
        mock_generate_password.return_value = "generatedpassword123"
        data = {
            "name": "Test Item",
            "username": "testuser",
            "password": "",
            "url": "http://example.com",
            "notes": "Test notes",
            "action": "generate_password",
        }
        response = self.client.post(reverse("passmanager:new_item"), data)
        self.assertEqual(
            response.context["form"].initial["password"], "generatedpassword123"
        )


class EditItemViewTests(TestCase):
    """
    Test case for the edit_item view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.other_user = CustomUser.objects.create_user(
            email="otheruser@example.com", password="password", username="otheruser"
        )
        self.client.login(email="testuser@example.com", password="password")
        self.item = Item.objects.create(
            name="Test Item",
            username="testuser",
            password="testpassword",
            url="http://example.com",
            notes="Test notes",
            owner=self.user,
        )

    def test_edit_item_view_redirect_if_not_logged_in(self):
        """
        Test to verify that non-logged-in users are redirected to the login page when trying to access the edit_item view.
        """
        self.client.logout()
        response = self.client.get(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(
            response, "/user/login/?next=/edit_item/{}/".format(self.item.id)
        )

    def test_edit_item_view_permission_denied_for_other_user(self):
        """
        Test to verify that other users cannot access the edit_item view of items they don't own.
        """
        self.client.login(email="otheruser@example.com", password="password")
        response = self.client.get(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id})
        )
        self.assertEqual(response.status_code, 404)

    def test_edit_item_view_post_save_action(self):
        """
        Verifies that an item's attributes are correctly updated after a save action.
        """
        data = {
            "name": "Modified Item",
            "username": "modifieduser",
            "password": "modifiedpassword",
            "url": "http://modified-example.com",
            "notes": "Modified notes",
            "action": "save",
        }
        response = self.client.post(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("passmanager:vault"))
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
            "username": "modifieduser",
            "password": "",
            "url": "http://modified-example.com",
            "notes": "Modified notes",
            "action": "generate_password",
        }
        response = self.client.post(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/edit_item.html")
        self.assertEqual(
            response.context["form"].initial["password"], "generatedpassword123"
        )

    def test_edit_item_view_post_delete_action(self):
        """
        Verifies that an item is correctly deleted when the delete action is triggered.
        """
        data = {
            "name": "Modified Item",
            "username": "modifieduser",
            "password": "modifiedpassword",
            "url": "http://modified-example.com",
            "notes": "Modified notes",
            "action": "delete",
        }
        response = self.client.post(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("passmanager:vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)  # Ensure item is deleted

    def test_edit_item_view_post_save_action_with_encryption(self):
        """
        Verifies that item attributes are correctly encrypted and decrypted after a save action.
        """
        data = {
            "name": "Encrypted Item",
            "username": "encrypteduser",
            "password": "encryptedpassword",
            "url": "http://example.com",
            "notes": "Encrypted notes",
            "action": "save",
        }
        response = self.client.post(
            reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data
        )
        self.assertRedirects(response, reverse("passmanager:vault"))

        self.item.refresh_from_db()
        self.item.decrypt_sensitive_fields()
        self.assertEqual(self.item.name, "Encrypted Item")
        self.assertEqual(self.item.username, "encrypteduser")
        self.assertEqual(self.item.password, "encryptedpassword")
        self.assertEqual(self.item.url, "http://example.com")
        self.assertEqual(self.item.notes, "Encrypted notes")


class DeleteItemViewTests(TestCase):
    """
    Test case for the delete_item view.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.other_user = CustomUser.objects.create_user(
            email="otheruser@example.com", password="password", username="otheruser"
        )
        self.client = Client()
        self.item = Item.objects.create(
            name="Test Item",
            username="testuser",
            password="testpassword",
            url="http://example.com",
            notes="Test notes",
            owner=self.user,
        )

    def test_delete_item_view_logged_in_owner(self):
        """
        Test that an owner can successfully delete their own item.
        """
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("passmanager:delete_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(response, reverse("passmanager:vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)  # Ensure item is deleted

    def test_delete_item_view_not_logged_in(self):
        """
        Test that a not logged-in user is redirected to the login page.
        """
        response = self.client.post(
            reverse("passmanager:delete_item", kwargs={"item_id": self.item.id})
        )
        self.assertRedirects(
            response, "/user/login/?next=/edit_item/{}/delete".format(self.item.id)
        )


class PasswordGeneratorViewTests(TestCase):
    """
    Test case for the password_generator view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")

    def test_password_generator_view_get(self):
        """
        Test GET request to password_generator view returns form.
        """
        response = self.client.get(reverse("passmanager:password_generator"))
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

        response = self.client.post(reverse("passmanager:password_generator"), data)
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

        response = self.client.post(reverse("passmanager:password_generator"), data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)
        self.assertIn("length", response.context["form"].errors)

    def test_password_generator_view_post_empty_data(self):
        """
        Test POST request with empty data returns form with initial values.
        """
        response = self.client.post(reverse("passmanager:password_generator"), {})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)
        self.assertEqual(
            response.context["password"], ""
        )  # Ensure password remains empty


class DownloadCsvViewTest(TestCase):
    """
    Test case for the download_csv view.
    """

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")

        self.item = Item(
            name="Test Item",
            username="testuser",
            password="testpassword",
            url="https://example.com",
            notes="Test notes",
            owner=self.user,
        )
        self.item.encrypt_sensitive_fields()
        self.item.save()

    def test_download_csv(self):
        """
        Test csv file returns with properly decrypted user data.
        """
        response = self.client.get(reverse("passmanager:download_csv"))

        # Verify response status & headers
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("PassManager Passwords.csv", response["Content-Disposition"])

        # Decode csv content & validate header
        content = response.content.decode("utf-8")
        reader = csv.reader(content.splitlines())
        header = next(reader)
        self.assertEqual(header, ["name", "username", "password", "url", "notes"])

        # Validate decrypted csv data rows
        rows = list(reader)
        self.assertEqual(len(rows), 1)  # Only 1 row of data

        self.item.decrypt_sensitive_fields()
        self.assertEqual(
            rows[0],
            [
                "Test Item",
                "testuser",
                "testpassword",
                "https://example.com",
                "Test notes",
            ],
        )


class UploadCsvViewTests(TestCase):
    """
    Test case for the upload_csv view.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")
        self.upload_url = reverse("passmanager:upload_csv")

    def test_upload_csv_view_status_code_and_template(self):
        """
        Test GET request renders the upload form.
        """
        response = self.client.get(self.upload_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/upload_csv.html")
        self.assertIsInstance(response.context["form"], ImportPasswordsForm)

    def test_valid_csv_upload(self):
        """
        Test valid csv upload saves encrypted data to the database.
        """
        csv_content = b"name,username,password,url,notes\nTest user,test_user,test_pass,example.com,example notes"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        # Post csv file to the view
        response = self.client.post(
            self.upload_url, data={"csv_file": file}, follow=True
        )
        self.assertRedirects(response, reverse("passmanager:vault"))
        self.assertEqual(Item.objects.count(), 1)

        item = Item.objects.first()
        item.decrypt_sensitive_fields()

        self.assertEqual(item.name, "Test user")
        self.assertEqual(item.username, "test_user")
        self.assertEqual(item.password, "test_pass")
        self.assertEqual(item.url, "example.com")
        self.assertEqual(item.notes, "example notes")
        self.assertEqual(item.owner, self.user)

    def test_invalid_csv_header(self):
        """
        Test csv upload with invalid headers.
        """
        csv_content = b"wrong_header1,wrong_header2,wrong_header3\ndata1,data2,data3"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        # Post csv file to the view
        response = self.client.post(
            self.upload_url, data={"csv_file": file}, follow=True
        )

        self.assertRedirects(response, self.upload_url)
        self.assertEqual(Item.objects.count(), 0)


class PasswordCheckupViewTests(TestCase):
    """
    Test case for the password_checkup view.
    """

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.encryption_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="password", username="testuser"
        )
        self.client.login(email="testuser@example.com", password="password")

        self.item1 = Item(
            name="Test Item 1",
            username="testuser1",
            password="testpassword12",
            url="http://example.com",
            notes="Test notes",
            owner=self.user,
        )
        self.item2 = Item(
            name="Test Item 2",
            username="testuser2",
            password="tEst__pA$$word",
            url="http://example.com",
            notes="Test notes",
            owner=self.user,
        )

        self.item1.encrypt_sensitive_fields()
        self.item1.save()
        self.item2.encrypt_sensitive_fields()
        self.item2.save()

    @patch("passmanager.views.check_password")
    def test_password_checkup(self, mock_check_password):
        """
        Test for check if the password has been pwned.
        """
        mock_check_password.side_effect = lambda password: {
            # Fake values for testing
            "testpassword12": 4,
            "tEst__pA$$word": 0,
        }.get(password, 0)

        response = self.client.get(reverse("passmanager:password_checkup"))
        results = response.context["results"]

        # Ensure the view uses the correct template
        self.assertTemplateUsed(response, "passmanager/password_checkup.html")

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["name"], "Test Item 1")
        self.assertEqual(results[0]["status"], "Exposed 4 time(s)")
        self.assertEqual(results[0]["severity"], "High")
        self.assertEqual(results[1]["name"], "Test Item 2")
        self.assertEqual(results[1]["status"], "No breaches found.")
        self.assertEqual(results[1]["severity"], "Low")
