"""
This module contains test cases for the following classes:
* ItemForm (validation and saving functionality)
* PasswordGeneratorForm (validation and functionality)
"""

from django.test import TestCase
from django.contrib.auth import get_user_model

from ..forms import ItemForm, PasswordGeneratorForm
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
            website="example.com",
            username="test_username",
            password="test_password",
            notes="Test notes",
            owner=self.test_user,
        )

    def test_item_form_valid(self):
        """
        Test that the form is valid when correct data is provided.
        """
        form_data = {
            "name": "Updated Item Name",
            "website": "updated-example.com",
            "username": "updated_username",
            "password": "updated_password",
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
            "website": "new-example.com",
            "username": "new_username",
            "password": "new_password",
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
            "website": "updated-example.com",
            "username": "updated_username",
            "password": "updated_password",
            "notes": "Updated notes",
        }
        form = ItemForm(instance=self.test_item, data=form_data)
        self.assertTrue(form.is_valid())
        form.save()
        self.test_item.refresh_from_db()
        self.assertEqual(self.test_item.name, "Updated Item")

    def test_item_form_required_fields(self):
        """
        Test that the form is valid when required fields are missing.
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
