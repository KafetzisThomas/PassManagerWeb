from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class CustomUserModelTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")

    def test_valid_user_creation(self):
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(self.user.email, "user@test.com")
        self.assertTrue(self.user.check_password("Str0ng_p@ssword"))
        self.assertIsNotNone(self.user.encryption_salt)
        self.assertEqual(len(self.user.encryption_salt), 44)

    def test_save_preserves_existing_encryption_salt(self):
        original_salt = self.user.encryption_salt
        self.user.username = "new_username"
        self.user.save()
        self.assertEqual(self.user.encryption_salt, original_salt)
