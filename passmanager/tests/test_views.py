import csv
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch
from django.urls import reverse
from ..forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm
from ..models import Item


class BaseUserTestCase(TestCase):
    """
    Setup users for reuse in multiple test classes.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.user2 = self.user_model.objects.create_user(
            email="tester2@example.com", password="password456", username="tester2"
        )
        self.client.login(email="tester@example.com", password="password123")


class VaultViewTests(BaseUserTestCase):
    """
    Test case for the vault view.
    """
    def setUp(self):
        super().setUp()
        # Create test items for both users
        for i in range(5):
            Item.objects.create(owner=self.user, name=f"Item {i}", date_added=f"2023-01-0{i + 1}")
            Item.objects.create(owner=self.user2, name=f"Other Item {i}", date_added=f"2023-01-0{i + 1}")

    def test_vault_view_redirect_if_not_logged_in(self):
        """
        Test if the vault view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("passmanager:vault"))
        self.assertRedirects(response, "/user/login/?next=/")

    def test_vault_view_status_code_and_template(self):
        """
        Test if the vault view returns a status code 200 & uses the correct template.
        """
        response = self.client.get(reverse("passmanager:vault"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/vault.html")

    def test_vault_view_items_for_logged_in_user(self):
        """
        Test if the vault view returns items only for the logged-in user.
        """
        response = self.client.get(reverse("passmanager:vault"))
        items = response.context["items"]
        for item in items:
            self.assertEqual(item.owner, self.user)


class NewItemViewTests(TestCase):
    """
    Test case for the new_item view.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.client.login(email="tester@example.com", password="password123")

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
        data = {"name": "Test Item", "username": "tester", "password": "password123",
                "url": "https://example.com", "notes": "Test notes", "group": "General", "action": "save"
        }
        response = self.client.post(reverse("passmanager:new_item"), data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        item = Item.objects.get(name="Test Item")
        self.assertNotEqual(item.username, "tester")
        self.assertNotEqual(item.password, "password123")
        self.assertNotEqual(item.notes, "Test notes")

        item.decrypt_sensitive_fields()
        self.assertEqual(item.name, "Test Item")
        self.assertEqual(item.username, "tester")
        self.assertEqual(item.password, "password123")
        self.assertEqual(item.url, "https://example.com")
        self.assertEqual(item.notes, "Test notes")
        self.assertEqual(item.group, "General")

    @patch("passmanager.views.generate_password")
    def test_new_item_view_post_generate_password_action(self, mock_generate_password):
        """
        Test if the new_item view correctly generates a password and updates the form.
        """
        mock_generate_password.return_value = "generatedpassword123"
        data = {"name": "Test Item", "username": "tester", "password": "", "url": "https://example.com",
                "notes": "Test notes", "group": "General", "action": "generate_password"
        }
        response = self.client.post(reverse("passmanager:new_item"), data)
        self.assertEqual(response.context["form"].initial["password"], "generatedpassword123")


class EditItemViewTests(BaseUserTestCase):
    """
    Test case for the edit_item view.
    """
    def setUp(self):
        super().setUp()
        self.item = Item.objects.create(
            name="Test Item", username="tester", password="testpassword",
            url="https://example.com", notes="Test notes", owner=self.user
        )

    def test_edit_item_view_redirect_if_not_logged_in(self):
        """
        Test if the edit_item view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}))
        self.assertRedirects(response, "/user/login/?next=/edit_item/{}/".format(self.item.id))

    def test_edit_item_view_permission_denied_for_tester2(self):
        """
        Test that other users cannot access items they don't own.
        """
        self.client.login(email="tester2@example.com", password="password456")
        response = self.client.get(reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}))
        self.assertEqual(response.status_code, 404)

    def test_edit_item_view_save_action(self):
        """
        Test that item's attributes are correctly updated after a save action.
        """
        data = {
            "name": "Modified Item", "username": "modifieduser", "password": "modifiedpassword",
            "url": "https://modified-example.com", "notes": "Modified notes", "group": "Modified Group", "action": "save"
        }
        response = self.client.post(reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        self.item.refresh_from_db()
        self.item.decrypt_sensitive_fields()
        self.assertEqual(self.item.name, "Modified Item")
        self.assertEqual(self.item.username, "modifieduser")
        self.assertEqual(self.item.password, "modifiedpassword")
        self.assertEqual(self.item.url, "https://modified-example.com")
        self.assertEqual(self.item.notes, "Modified notes")

    @patch("passmanager.views.generate_password")
    def test_edit_item_view_generate_password_action(self, mock_generate_password):
        """
        Test generate_password action generates a new password.
        """
        mock_generate_password.return_value = "generatedpassword123"
        data = {
            "name": "Modified Item", "username": "modifieduser", "password": "", "url": "https://modified-example.com",
            "notes": "Modified notes", "group": "Modified Group", "action": "generate_password"
        }
        response = self.client.post(reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data)
        self.assertEqual(response.context["form"].initial["password"], "generatedpassword123")

    def test_edit_item_view_delete_action(self):
        """
        Test item is correctly deleted when the delete action is triggered.
        """
        data = {"name": "Modified Item", "username": "modifieduser", "password": "modifiedpassword",
                "url": "https://modified-example.com", "notes": "Modified notes", "action": "delete"}
        response = self.client.post(reverse("passmanager:edit_item", kwargs={"item_id": self.item.id}), data)
        self.assertRedirects(response, reverse("passmanager:vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)  # Ensure item is deleted


class PasswordGeneratorViewTests(TestCase):
    """
    Test case for the password_generator view.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.client.login(email="tester@example.com", password="password123")

    def test_password_generator_view_status_code_and_template(self):
        """
        Test if the view returns status code 200 and uses the correct template.
        """
        response = self.client.get(reverse("passmanager:password_generator"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/password_generator.html")
        self.assertIsInstance(response.context["form"], PasswordGeneratorForm)

        # Ensure password is empty initially
        self.assertEqual(response.context["password"], "")

    @patch("passmanager.views.generate_password")
    def test_password_generator_view_valid_data(self, mock_generate_password):
        """
        Test if view generates a password with valid data.
        """
        mock_generate_password.return_value = "GeneratedPassword123"
        data = {"length": 12, "letters": True, "digits": True, "special_chars": False}
        response = self.client.post(reverse("passmanager:password_generator"), data)
        self.assertEqual(response.context["password"], "GeneratedPassword123")

    def test_password_generator_view_empty_data(self):
        """
        Test that view returns empty values with no input.
        """
        response = self.client.post(reverse("passmanager:password_generator"), {})
        self.assertEqual(response.context["password"], "")


class ExportCsvViewTests(TestCase):
    """
    Test case for the export_csv view.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.client.login(email="tester@example.com", password="password123")
        self.item = Item(name="Test Item", username="tester", password="testpassword", url="https://example.com",
                         notes="Test notes", group="General", owner=self.user)
        self.item.encrypt_sensitive_fields()
        self.item.save()

    def test_export_csv_view(self):
        """
        Test csv file returns with properly decrypted user data.
        """
        form_response = self.client.get(reverse("passmanager:export_csv"))

        # Verify we got the master password re-authentication form
        self.assertEqual(form_response.status_code, 200)
        self.assertEqual(form_response["Content-Type"], "text/html; charset=utf-8")

        csrf_token = form_response.context["csrf_token"]
        post_response = self.client.post(
            reverse("passmanager:export_csv"),
            data={"password": "password123", "csrfmiddlewaretoken": csrf_token},
            follow=True,
        )

        # Verify response status & headers
        self.assertEqual(post_response.status_code, 200)
        self.assertEqual(post_response["Content-Type"], "text/csv")
        self.assertIn("PassManager Passwords.csv", post_response["Content-Disposition"])

        # Decode csv content & validate header
        content = post_response.content.decode("utf-8")
        reader = csv.reader(content.splitlines())
        header = next(reader)
        self.assertEqual(header, ["name", "username", "password", "url", "notes", "group"])

        # Validate decrypted csv data rows
        rows = list(reader)
        self.assertEqual(len(rows), 1)  # Only 1 row of data

        self.item.decrypt_sensitive_fields()
        self.assertEqual(rows[0], second=[
            "Test Item", "tester", "testpassword", "https://example.com", "Test notes", "General"],
        )


class ImportCsvViewTests(TestCase):
    """
    Test case for the import_csv view.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.client.login(email="tester@example.com", password="password123")

    def test_import_csv_view_status_code_and_template(self):
        """
        Test if the view returns status code 200 and uses the correct template.
        """
        response = self.client.get(reverse("passmanager:import_csv"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passmanager/import_csv.html")
        self.assertIsInstance(response.context["form"], ImportPasswordsForm)

    def test_valid_csv_import(self):
        """
        Test valid csv import saves encrypted data to the database.
        """
        csv_content = b"name,username,password,url,notes,group\nExample Name,example_user,example_pass,example.com,example notes,General"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        # Post csv file to the view
        response = self.client.post(reverse("passmanager:import_csv"), data={"csv_file": file}, follow=True)
        self.assertRedirects(response, reverse("passmanager:vault"))
        self.assertEqual(Item.objects.count(), 1)

        item = Item.objects.first()
        item.decrypt_sensitive_fields()

        self.assertEqual(item.name, "Example Name")
        self.assertEqual(item.username, "example_user")
        self.assertEqual(item.password, "example_pass")
        self.assertEqual(item.url, "example.com")
        self.assertEqual(item.notes, "example notes")
        self.assertEqual(item.group, "General")
        self.assertEqual(item.owner, self.user)

    def test_invalid_csv_header(self):
        """
        Test csv import with invalid headers.
        """
        csv_content = b"wrong_header1,wrong_header2,wrong_header3\ndata1,data2,data3"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        # Post csv file to the view
        response = self.client.post(reverse("passmanager:import_csv"), data={"csv_file": file}, follow=True)
        self.assertRedirects(response, reverse("passmanager:import_csv"))
        self.assertEqual(Item.objects.count(), 0)


class PasswordCheckupViewTests(TestCase):
    """
    Test case for the password_checkup view.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", password="password123", username="tester"
        )
        self.client.login(email="tester@example.com", password="password123")
        self.item1 = Item(name="Test Item 1",username="tester1", password="testpassword12",
                          url="https://example.com",notes="Test notes", group="General", owner=self.user)
        self.item2 = Item(name="Test Item 2", username="tester2", password="tEst__pA$$word",
                          url="https://example.com", notes="Test notes", group="General", owner=self.user)
        self.item1.encrypt_sensitive_fields()
        self.item1.save()
        self.item2.encrypt_sensitive_fields()
        self.item2.save()

    @patch("passmanager.views.check_pwned_password")
    def test_password_checkup_view(self, mock_check_pwned_password):
        """
        Test checkup verifies if password has been pwned.
        """
        mock_check_pwned_password.side_effect = lambda password: {
            "testpassword12": 4, "tEst__pA$$word": 0}.get(password, 0)

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
