"""
This module contains test cases for the following views:
* home, vault
"""

from django.test import TestCase
from django.urls import reverse

from users.models import CustomUser
from passmanager.models import Item


class HomeViewTest(TestCase):
    """
    Test case for the home view.
    """

    def test_home_view_status_code(self):
        """
        Test if the home view returns a status code 200.
        """
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)

    def test_home_view_template_used(self):
        """
        Test if the home view uses the correct template.
        """
        response = self.client.get(reverse("home"))
        self.assertTemplateUsed(response, "passmanager/home.html")


class VaultViewTest(TestCase):
    """
    Test case for the vault view.
    """

    def setUp(self):
        """
        Set up test data and create a test user.
        """
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com", password="12345", username="testuser"
        )
        self.user2 = CustomUser.objects.create_user(
            email="otheruser@example.com", password="54321", username="otheruser"
        )

        self.client.login(email="testuser@example.com", password="12345")

        # Create test items for both users
        for i in range(5):
            Item.objects.create(
                owner=self.user, name=f"Item {i}", date_added=f"2023-01-0{i+1}"
            )
            Item.objects.create(
                owner=self.user2, name=f"Other Item {i}", date_added=f"2023-01-0{i+1}"
            )

    def test_vault_view_redirect_if_not_logged_in(self):
        """
        Test if the vault view redirects to the login page if not logged in.
        """
        self.client.logout()
        response = self.client.get(reverse("vault"))
        self.assertRedirects(response, "/user/login/?next=/vault/")

    def test_vault_view_status_code(self):
        """
        Test if the vault view returns a status code 200 for logged-in users.
        """
        response = self.client.get(reverse("vault"))
        self.assertEqual(response.status_code, 200)

    def test_vault_view_template_used(self):
        """
        Test if the vault view uses the correct template.
        """
        response = self.client.get(reverse("vault"))
        self.assertTemplateUsed(response, "passmanager/vault.html")

    def test_vault_view_items_for_logged_in_user(self):
        """
        Test if the vault view returns items only for the logged-in user.
        """
        response = self.client.get(reverse("vault"))
        page_obj = response.context["page_obj"]
        items = page_obj.object_list
        for item in items:
            self.assertEqual(item.owner, self.user)

    def test_vault_view_pagination(self):
        """
        Test if the vault view paginates items correctly.
        """
        response = self.client.get(reverse("vault"))
        page_obj = response.context["page_obj"]
        self.assertTrue(page_obj.has_next())
        self.assertEqual(len(page_obj), 3)

        response = self.client.get(reverse("vault") + "?page=2")
        page_obj = response.context["page_obj"]
        self.assertFalse(page_obj.has_next())
        self.assertEqual(len(page_obj), 2)
