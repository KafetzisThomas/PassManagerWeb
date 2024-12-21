"""
This module contains test cases for the following classes:
* ItemForm (validation and saving functionality)
* PasswordGeneratorForm (validation and functionality)
"""

from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model

from ..forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm
from ..models import Item


class ItemFormTests(TestCase):
    """
    Test suite for the ItemForm.
    """

    def setUp(self):
        """
        Set up the test environment by creating a test user and a test item.
        """
        self.test_user = get_user_model().objects.create_user(
            username="testuser", email="testuser@example.com", password="password123"
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
        form_data = {
            "name": "Updated Item Name",
            "username": "updated_username",
            "password": "updated_password",
            "url": "updated-example.com",
            "notes": "Updated notes",
        }
        form = ItemForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_item_form_save(self):
        """
        Test that the form's save method creates a new item.
        """
        form_data = {
            "name": "New Item",
            "username": "new_username",
            "password": "new_password",
            "url": "new-example.com",
            "notes": "New notes",
        }
        form = ItemForm(data=form_data)
        self.assertTrue(form.is_valid())
        item = form.save(commit=False)
        item.owner = self.test_user
        item.save()
        self.assertEqual(Item.objects.filter(name="New Item").count(), 1)

    def test_item_form_update(self):
        """
        Test that the form's save method updates an existing item.
        """
        form_data = {
            "name": "Updated Item",
            "username": "updated_username",
            "password": "updated_password",
            "url": "updated-example.com",
            "notes": "Updated notes",
        }
        form = ItemForm(instance=self.test_item, data=form_data)
        self.assertTrue(form.is_valid())
        form.save()
        self.test_item.refresh_from_db()
        self.assertEqual(self.test_item.name, "Updated Item")

    def test_item_form_other_fields(self):
        """
        Test that the form is valid when other fields are missing.
        """
        form_data = {
            "name": "Test Item",
        }
        form = ItemForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_item_form_empty_data(self):
        """
        Test that the form is invalid when empty data is provided.
        """
        form = ItemForm(data={})
        self.assertFalse(form.is_valid())


class PasswordGeneratorFormTests(TestCase):
    """
    Test suite for the PasswordGeneratorForm.
    """

    def test_form_valid(self):
        """
        Test that the form is valid when correct data is provided.
        """
        form_data = {
            "length": 12,
            "letters": True,
            "digits": True,
            "special_chars": False,
        }
        form = PasswordGeneratorForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_invalid_length_too_short(self):
        """
        Test that the form is invalid when the length is too short.
        """
        form_data = {
            "length": 4,
            "letters": True,
            "digits": True,
            "special_chars": False,
        }
        form = PasswordGeneratorForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("length", form.errors)
        self.assertEqual(
            form.errors["length"][0], "Ensure this value is greater than or equal to 8."
        )

    def test_form_invalid_length_too_long(self):
        """
        Test that the form is invalid when the length is too long.
        """
        form_data = {
            "length": 35,
            "letters": True,
            "digits": True,
            "special_chars": False,
        }
        form = PasswordGeneratorForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("length", form.errors)
        self.assertEqual(
            form.errors["length"][0], "Ensure this value is less than or equal to 32."
        )

    def test_form_invalid_when_letters_unchecked(self):
        """
        Test that the form is invalid when letters option is unchecked.
        """
        form_data = {
            "length": 12,
            "letters": False,
            "digits": True,
            "special_chars": True,
        }
        form = PasswordGeneratorForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("letters", form.errors)
        self.assertEqual(form.errors["letters"][0], "This field is required.")

    def test_form_initial_values(self):
        """
        Test that the form initializes with correct initial values.
        """
        form = PasswordGeneratorForm()
        self.assertEqual(form.fields["length"].initial, 12)
        self.assertTrue(form.fields["letters"].initial)
        self.assertTrue(form.fields["digits"].initial)
        self.assertTrue(form.fields["special_chars"].initial)


class ImportPasswordsFormTests(TestCase):
    """
    Test suite for the ImportPasswordsForm.
    """

    def test_valid_csv_file_upload(self):
        """
        Test that a valid csv file is accepted.
        """
        csv_content = b"name,username,password,url,notes\Test User,test_user,test_pass,example.com,example notes"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")
        form = ImportPasswordsForm(data={}, files={"csv_file": file})
        self.assertTrue(form.is_valid(), form.errors)

    def test_invalid_file_extension(self):
        """
        Test that a file with an invalid extension is rejected.
        """
        csv_content = b"Dummy content"
        file = SimpleUploadedFile("test.txt", csv_content, content_type="text/plain")
        form = ImportPasswordsForm(data={}, files={"csv_file": file})
        self.assertFalse(form.is_valid(), form.errors)
