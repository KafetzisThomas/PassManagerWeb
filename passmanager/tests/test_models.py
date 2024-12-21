"""
This module contains test cases for the Item model.
The tests cover various aspects of the model, including item creation,
field validations, foreign key constraints, and the __str__ method.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from ..models import Item


class ItemModelTests(TestCase):
    """
    Test suite for the Item model.
    """

    def setUp(self):
        """
        Set up the test environment by creating a user and defining item data.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", username="testuser", password="password123"
        )
        self.item_data = {
            "name": "Test Item",
            "username": "itemuser",
            "password": "password123",
            "url": "https://example.com",
            "notes": "Some notes about the item",
            "owner": self.user,
        }

    def test_create_item(self):
        """
        Test that an item can be created with the given data.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(item.name, self.item_data["name"])
        self.assertEqual(item.username, self.item_data["username"])
        self.assertEqual(item.password, self.item_data["password"])
        self.assertEqual(item.url, self.item_data["url"])
        self.assertEqual(item.notes, self.item_data["notes"])
        self.assertEqual(item.owner, self.item_data["owner"])
        self.assertTrue((timezone.now() - item.date_added).seconds < 10)

    def test_str_method(self):
        """
        Test that the __str__ method returns the item's name.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(str(item), item.name)

    def test_owner_foreign_key(self):
        """
        Test the foreign key constraint on the owner field.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(item.owner, self.user)

    def test_field_max_length(self):
        """
        Test the maximum length of the fields.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(item._meta.get_field("name").max_length, 100)
        self.assertEqual(item._meta.get_field("username").max_length, 100)
        self.assertEqual(item._meta.get_field("password").max_length, 100)
        self.assertEqual(item._meta.get_field("url").max_length, 100)
        self.assertEqual(item._meta.get_field("notes").max_length, 100)

    def test_item_deletion(self):
        """
        Test that an item is deleted when the owner is deleted.
        """
        item = Item.objects.create(**self.item_data)
        self.user.delete()
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=item.id)
