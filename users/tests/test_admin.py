from django.test import TestCase, Client
from django.contrib import admin
from django.contrib.admin.sites import AdminSite

from ..admin import CustomUserAdmin
from ..models import CustomUser


class CustomUserAdminTest(TestCase):
    """
    Test case for the CustomUserAdmin class.
    """

    def setUp(self):
        """
        Set up the test environment.
        """
        self.client = Client()
        self.admin_user = CustomUser.objects.create_superuser(
            email="admin@example.com", username="admin", password="adminpassword"
        )
        self.client.force_login(self.admin_user)
        self.site = AdminSite()

    def test_admin_list_display(self):
        """
        Test that the list display fields are correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        self.assertEqual(
            custom_user_admin.list_display,
            (
                "username",
                "email",
                "enable_2fa",
                "otp_secret",
                "session_timeout",
                "is_active",
                "is_staff",
                "is_superuser",
                "last_login",
            ),
        )

    def test_admin_list_filter(self):
        """
        Test that the list filter fields are correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        self.assertEqual(
            custom_user_admin.list_filter, ("is_active", "is_staff", "is_superuser")
        )

    def test_admin_fieldsets(self):
        """
        Test that the fieldsets are correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        expected_fieldsets = (
            (None, {"fields": ("username", "email", "password")}),
            (
                "Permissions",
                {
                    "fields": (
                        "is_staff",
                        "is_active",
                        "is_superuser",
                        "groups",
                        "user_permissions",
                    )
                },
            ),
            (
                "Session Settings",
                {"fields": ("session_timeout",)},
            ),
            ("Dates", {"fields": ("last_login", "date_joined")}),
        )
        self.assertEqual(custom_user_admin.fieldsets, expected_fieldsets)

    def test_admin_add_fieldsets(self):
        """
        Test that the add fieldsets are correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        expected_add_fieldsets = (
            (
                None,
                {
                    "classes": ("wide",),
                    "fields": (
                        "username",
                        "email",
                        "password1",
                        "password2",
                        "is_staff",
                        "is_active",
                        "session_timeout",
                    ),
                },
            ),
        )
        self.assertEqual(custom_user_admin.add_fieldsets, expected_add_fieldsets)

    def test_admin_search_fields(self):
        """
        Test that the search fields are correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        self.assertEqual(custom_user_admin.search_fields, ("email",))

    def test_admin_ordering(self):
        """
        Test that the ordering is correctly configured.
        """
        custom_user_admin = CustomUserAdmin(CustomUser, self.site)
        self.assertEqual(custom_user_admin.ordering, ("email",))

    def test_admin_integration(self):
        """
        Test that the CustomUserAdmin is correctly registered with Django admin.
        """
        self.assertIn(CustomUser, admin.site._registry)
        self.assertIsInstance(admin.site._registry[CustomUser], CustomUserAdmin)
