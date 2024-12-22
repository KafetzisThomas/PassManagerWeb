"""
This module contains test cases for the clean_db management command.
The tests cover the functionality of the clean_db command, which is responsible
for deleting rows in the CustomUser model where the 'last_login' field is NULL.
"""

from django.core.management import call_command
from django.test import TestCase
from django.utils.timezone import make_aware
from datetime import datetime
from io import StringIO
from ..models import CustomUser


class CleanDBCommandTestCase(TestCase):
    """
    Test suite for the clean_db management command.
    """

    def setUp(self):
        """
        Set up test data with NULL values in 'last_login' field for CustomUser.
        """
        CustomUser.objects.create(
            email="user1@example.com", username="user1", last_login=None
        )
        CustomUser.objects.create(
            email="user2@example.com", username="user2", last_login=None
        )
        CustomUser.objects.create(
            email="user3@example.com",
            username="user3",
            last_login=make_aware(datetime(2024, 1, 1, 12, 0, 0)),
        )

    def test_clean_db_command(self):
        """
        Test deleting rows with NULL value in 'last_login' column.
        """
        out = StringIO()  # Capture command output
        call_command("clean_db", stdout=out)

        # Check if the command output contains the success message
        output = out.getvalue()
        self.assertIn("Deleted", output)
        self.assertIn("rows from", output)
        self.assertIn("where last_login was NULL", output)

        # Verify that rows with NULL value in 'last_login' column were deleted
        self.assertEqual(CustomUser.objects.filter(last_login=None).count(), 0)
