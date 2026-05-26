import base64
from django.contrib.auth import get_user_model
from django.test import TestCase
from ..models import Item

User = get_user_model()

class ItemModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.item = Item.objects.create(
            name="Test Item",
            username="itemuser",
            password="password123",
            url="https://example.com",
            notes="Some notes",
            owner=self.user
        )

    def test_get_key_is_valid_length(self):
        key1 = self.item.get_key() 
        key2 = self.item.get_key()
        self.assertEqual(key1, key2)

        key_bytes = base64.urlsafe_b64decode(key1)
        self.assertIsInstance(key1, bytes)
        self.assertEqual(len(key_bytes), 32)  # AES 256 GCM = 32 byte key

    def test_create_item_success(self):
        original_username = self.item.username
        original_password = self.item.password
        original_notes = self.item.notes

        self.item.encrypt_sensitive_fields()

        self.assertEqual(self.item.name, "Test Item")
        self.assertNotEqual(self.item.username, original_username)
        self.assertNotEqual(self.item.password, original_password)
        self.assertNotEqual(self.item.notes, original_notes)        
        self.assertEqual(self.item.url, "https://example.com")

        self.item.decrypt_sensitive_fields()

        self.assertEqual(self.item.username, original_username)
        self.assertEqual(self.item.password, original_password)
        self.assertEqual(self.item.notes, original_notes)
