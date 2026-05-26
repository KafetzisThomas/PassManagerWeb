import csv
import hashlib
from io import StringIO
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from ..models import Item

User = get_user_model()


class VaultViewTests(TestCase):

    def setUp(self):
        self.url = reverse("passmanager:vault")
        self.user1 = User.objects.create_user(
            email="user1@test.com", username="user1", password="Str0ng_p@ssword"
        )
        self.user2 = User.objects.create_user(
            email="user2@test.com", username="user2", password="Str0ng_p@ssword"
        )
        self.item1 = Item.objects.create(name="Google", owner=self.user1)
        self.item2 = Item.objects.create(name="GitHub", owner=self.user1)
        self.item3 = Item.objects.create(name="Amazon", owner=self.user2)

    def test_unauthenticated_user_redirects_to_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_vault_enforces_data_isolation(self):
        self.client.login(email="user1@test.com", password="Str0ng_p@ssword")
        response = self.client.get(self.url)
        items = response.context["items"]

        self.assertEqual(items.count(), 2)
        self.assertIn(self.item1, items)
        self.assertIn(self.item2, items)
        self.assertNotIn(self.item3, items)

    def test_vault_search_filter(self):
        self.client.login(email="user1@test.com", password="Str0ng_p@ssword")
        response = self.client.get(self.url, {"search": "Git"})

        items = response.context["items"]
        self.assertEqual(items.count(), 1)
        self.assertIn(self.item2, items)


class NewItemViewTests(TestCase):

    def setUp(self):
        self.url = reverse("passmanager:new_item")
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")
        self.form_data = {
            "name": "Test Item",
            "username": "itemuser",
            "password": "password123",
            "url": "https://example.com",
            "notes": "Test notes"
        }

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_new_item_view_save(self):
        response = self.client.post(self.url, self.form_data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        item = Item.objects.get(name="Test Item")
        self.assertNotEqual(item.username, "itemuser")
        self.assertNotEqual(item.password, "password123")
        self.assertEqual(item.url, "https://example.com")
        self.assertNotEqual(item.notes, "Test notes")


class EditItemViewTests(TestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(email="user1@test.com", username="user1", password="Str0ng_p@ssword")
        self.user2 = User.objects.create_user(email="user2@test.com", username="user2", password="Str0ng_p@ssword")
        self.client.login(email="user1@test.com", password="Str0ng_p@ssword")
        self.item = Item.objects.create(
            name="Test Item",
            username="itemuser",
            password="password123",
            url="https://example.com",
            notes="Test notes",
            owner=self.user1
        )
        self.item.encrypt_sensitive_fields()
        self.item.save()

        self.url = reverse("passmanager:edit_item", kwargs={"item_id": self.item.id})

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_edit_item_view_permission_denied_for_tester2(self):
        self.client.logout()
        self.client.login(email="user2@test.com", password="Str0ng_p@ssword")

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)

    def test_edit_item_view_get_decrypts_data(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        self.assertEqual(form.initial["password"], "password123")

    def test_edit_item_view_save_action(self):
        data = {
            "name": "Modified Item",
            "username": "modifieduser",
            "password": "modifiedpassword",
            "url": "https://modified-example.com",
            "notes": "Modified notes"
        }
        response = self.client.post(self.url, data)
        self.assertRedirects(response, reverse("passmanager:vault"))

        self.item.refresh_from_db()
        self.assertNotEqual(self.item.password, "modifiedpassword")

        self.item.decrypt_sensitive_fields()
        self.assertEqual(self.item.name, "Modified Item")
        self.assertEqual(self.item.password, "modifiedpassword")

    def test_edit_item_view_delete_action(self):
        data = {"action": "delete"}
        response = self.client.post(self.url, data)
        self.assertRedirects(response, reverse("passmanager:vault"))
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=self.item.id)


class ExportCsvViewTests(TestCase):

    def setUp(self):
        self.url = reverse("passmanager:export_csv")
        self.user1 = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.user2 = User.objects.create_user(email="user2@test.com", username="user2", password="Str0ng_p@ssword")
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")
        self.item = Item(
            name="Test Item",
            username="itemuser",
            password="password123",
            url="https://example.com",
            notes="Test notes",
            owner=self.user1
        )
        self.item.encrypt_sensitive_fields()
        self.item.save()

        Item.objects.create(name="Test Item 2", owner=self.user2)

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_export_csv_view_decrypts_and_isolates_data(self):
        response = self.client.post(self.url, {"password": "Str0ng_p@ssword"}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("passmanagerweb_passwords.csv", response["Content-Disposition"])

        content = response.content.decode("utf-8")
        reader = csv.reader(StringIO(content))
        rows = list(reader)

        self.assertEqual(rows[0], ["name", "username", "password", "url", "notes"])

        self.assertEqual(len(rows), 2)  # 1 header row + 1 data row
        self.assertEqual(
            rows[1], 
            ["Test Item", "itemuser", "password123", "https://example.com", "Test notes"]
        )


class ImportCsvViewTests(TestCase):

    def setUp(self):
        self.url = reverse("passmanager:import_csv")
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_valid_csv_import(self):
        csv_content = b"name,username,password,url,notes\nExample Name,example_user,example_pass,example.com,example notes"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        response = self.client.post(self.url, data={"csv_file": file})
        self.assertRedirects(response, reverse("passmanager:vault"))
        self.assertEqual(Item.objects.count(), 1)

        item = Item.objects.first()
        self.assertNotEqual(item.password, "example_pass")

        item.decrypt_sensitive_fields()
        self.assertEqual(item.name, "Example Name")
        self.assertEqual(item.username, "example_user")
        self.assertEqual(item.password, "example_pass")
        self.assertEqual(item.url, "example.com")
        self.assertEqual(item.notes, "example notes")
        self.assertEqual(item.owner, self.user)

    def test_invalid_csv_header(self):
        csv_content = b"wrong_header1,wrong_header2,wrong_header3\ndata1,data2,data3"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")

        response = self.client.post(self.url, data={"csv_file": file})
        self.assertRedirects(response, self.url)
        self.assertEqual(Item.objects.count(), 0)


class PasswordCheckupViewTests(TestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.user2 = User.objects.create_user(email="user2@test.com", username="user2", password="Str0ng_p@ssword")
        self.client.login(email="user@test.com", password="Str0ng_p@ssword")

        self.valid_item = Item(
            name="Test Item 1",
            username="itemtest1",
            password="password123",
            owner=self.user1
        )
        self.valid_item.encrypt_sensitive_fields()
        self.valid_item.save()

        self.empty_item = Item(
            name="Test Item 2",
            username="itemtest2",
            password="",
            owner=self.user1
        )        
        self.empty_item.encrypt_sensitive_fields()
        self.empty_item.save()

        Item.objects.create(name="Test Item 3", owner=self.user2)

        self.url = reverse("passmanager:checkup_api")

    def test_unauthenticated_user_redirects_to_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_checkup_api_generates_correct_hashes_and_isolates_data(self):
        response = self.client.get(self.url)
        data = response.json()
        items = data["items"]

        # expected 1 item, ignored blank password one and wrong owner's item
        self.assertEqual(len(items), 1)

        expected_full_hash = hashlib.sha1(b"password123").hexdigest().upper()
        expected_prefix = expected_full_hash[:5]
        expected_suffix = expected_full_hash[5:]

        api_item = items[0]
        self.assertEqual(api_item["name"], "Test Item 1")
        self.assertEqual(api_item["hash_prefix"], expected_prefix)
        self.assertEqual(api_item["hash_suffix"], expected_suffix)
