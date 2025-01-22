from cryptography.fernet import Fernet
from django.test import TestCase
from django.contrib.auth import get_user_model
from ..models import Item


class ItemModelTests(TestCase):
    """
    Test suite for the Item model.
    """

    def setUp(self):
        """
        Set up test data and create test users.
        """
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            email="testuser@example.com", username="testuser", password="password123"
        )

        # Random salt for testing encryption
        self.user.encryption_salt = "test_salt"
        self.user.save()

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

    def test_field_max_length(self):
        """
        Test the maximum length of the fields.
        """
        item = Item.objects.create(**self.item_data)
        self.assertEqual(item._meta.get_field("name").max_length, 50)
        self.assertEqual(item._meta.get_field("username").max_length, 500)
        self.assertEqual(item._meta.get_field("password").max_length, 500)
        self.assertEqual(item._meta.get_field("url").max_length, 50)
        self.assertEqual(item._meta.get_field("notes").max_length, 1500)

    def test_item_deletion(self):
        """
        Test that an item is deleted when the owner is deleted.
        """
        item = Item.objects.create(**self.item_data)
        self.user.delete()
        with self.assertRaises(Item.DoesNotExist):
            Item.objects.get(id=item.id)

    def test_encrypt_sensitive_fields(self):
        """
        Test the encryption of sensitive fields.
        """
        item = Item.objects.create(**self.item_data)
        og_username = item.username
        og_password = item.password
        og_notes = item.notes

        item.encrypt_sensitive_fields()

        # Ensure fields differ from og values
        self.assertNotEqual(item.username, og_username)
        self.assertNotEqual(item.password, og_password)
        self.assertNotEqual(item.notes, og_notes)

    def test_decrypt_sensitive_fields(self):
        """
        Test the decryption of sensitive fields.
        """
        item = Item.objects.create(**self.item_data)
        item.encrypt_sensitive_fields()
        encrypted_username = item.username
        encrypted_password = item.password
        encrypted_notes = item.notes

        item.decrypt_sensitive_fields()

        # Ensure fields are decrypted back to og values
        self.assertNotEqual(item.username, encrypted_username)
        self.assertNotEqual(item.password, encrypted_password)
        self.assertNotEqual(item.notes, encrypted_notes)
        self.assertEqual(item.username, self.item_data["username"])
        self.assertEqual(item.password, self.item_data["password"])
        self.assertEqual(item.notes, self.item_data["notes"])

    def test_get_key(self):
        """
        Test that the encryption key is correctly derived.
        """
        item = Item.objects.create(**self.item_data)
        key = item.get_key()

        # Ensure derived key is valid
        self.assertIsInstance(key, bytes)
        self.assertTrue(Fernet(key))
