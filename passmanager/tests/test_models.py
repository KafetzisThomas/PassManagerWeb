import os
import base64
from django.contrib.auth import get_user_model
from django.test import TestCase
from ..models import Item


class ItemModelTests(TestCase):
    """
    Test suite for the Item model.
    """
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="tester@example.com", username="tester", password="password123"
        )

        # Random salt for testing encryption
        self.user.encryption_salt = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self.user.save()

        self.item_data = {
            "name": "Test Item", "username": "itemuser", "password": "password123", "url": "https://example.com",
            "notes": "Some notes about the item", "group": "General", "owner": self.user
        }

    def test_create_item(self):
        """
        Test that an item can be created with the given data.
        """
        item = Item.objects.create(**self.item_data)
        item.encrypt_sensitive_fields()

        # Ensure fields differ from og values
        self.assertNotEqual(item.username, self.item_data["username"])
        self.assertNotEqual(item.password, self.item_data["password"])
        self.assertNotEqual(item.notes, self.item_data["notes"])

        item.decrypt_sensitive_fields()

        # Ensure fields are decrypted back to og values
        self.assertEqual(item.name, self.item_data["name"])
        self.assertEqual(item.username, self.item_data["username"])
        self.assertEqual(item.password, self.item_data["password"])
        self.assertEqual(item.url, self.item_data["url"])
        self.assertEqual(item.notes, self.item_data["notes"])
        self.assertEqual(item.group, self.item_data["group"])
        self.assertEqual(item.owner, self.item_data["owner"])

    def test_field_max_length(self):
        """
        Test the maximum length of the fields.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(item._meta.get_field("name").max_length, 50)
        self.assertEqual(item._meta.get_field("url").max_length, 50)
        self.assertEqual(item._meta.get_field("group").max_length, 50)

    def test_item_deletion(self):
        """
        Test that an item is deleted when the owner is deleted.
        """
        item = Item.objects.create(**self.item_data)
        self.user.delete()
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=item.id)

    def test_get_key(self):
        """
        Test that the encryption key is correctly derived.
        """
        item = Item.objects.create(**self.item_data)
        key = item.get_key()
        key_bytes = base64.urlsafe_b64decode(key)

        # Ensure derived key is valid
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key_bytes), 32)  # AES 256 GCM = 32 byte key
