from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.datastructures import MultiValueDict
from ..forms import ItemForm, ImportPasswordsForm
from ..models import Item


class ItemFormTests(TestCase):
    """
    Test suite for the ItemForm.
    """
    def setUp(self):
        self.test_user = get_user_model().objects.create_user(
            username="tester", email="tester@example.com", password="password123"
        )
        self.test_item = Item.objects.create(
            name="Test Item",
            username="test_username",
            password="test_password",
            url="example.com",
            notes="Test notes",
            owner=self.test_user,
        )

    def test_item_form_valid(self):
        """
        Test that the form is valid when correct data is provided.
        """
        form_data = {"name": "New Item", "username": "new_username", "password": "new_password",
                     "url": "new-example.com", "notes": "New notes"}
        form = ItemForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors)
        item = form.save(commit=False)
        item.owner = self.test_user
        item.save()
        self.assertEqual(Item.objects.filter(name="New Item").count(), 1)

    def test_item_form_update(self):
        """
        Test that the form updates an existing item.
        """
        form_data = {"name": "Updated Item", "username": "updated_username", "password": "updated_password",
                     "url": "updated-example.com", "notes": "Updated notes"}
        form = ItemForm(instance=self.test_item, data=form_data)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.test_item.refresh_from_db()
        self.assertEqual(self.test_item.name, "Updated Item")

    def test_item_form_other_fields(self):
        """
        Test that the form is valid when other fields are missing.
        """
        form_data = {"name": "Test Item"}
        form = ItemForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors)

    def test_item_form_empty_data(self):
        """
        Test that the form is invalid when empty data is provided.
        """
        form = ItemForm(data={})
        self.assertFalse(form.is_valid(), form.errors)


class ImportPasswordsFormTests(TestCase):
    """
    Test suite for the ImportPasswordsForm.
    """
    def test_valid_csv_file_import(self):
        """
        Test that a valid csv file is accepted.
        """
        csv_content = b"name,username,password,url,notes\nExample name,example_user,example_pass,example.com,example notes"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")
        form = ImportPasswordsForm(data={}, files=MultiValueDict({"csv_file": [file]}))
        self.assertTrue(form.is_valid(), form.errors)

    def test_invalid_file_extension(self):
        """
        Test that a file with an invalid extension is rejected.
        """
        csv_content = b"Dummy content"
        file = SimpleUploadedFile("test.txt", csv_content, content_type="text/plain")
        form = ImportPasswordsForm(data={}, files=MultiValueDict({"csv_file": [file]}))
        self.assertFalse(form.is_valid(), form.errors)
