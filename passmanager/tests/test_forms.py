"""
This module contains test cases for the ItemForm class.
The tests cover form validation and saving functionality.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model

from ..forms import ItemForm
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
