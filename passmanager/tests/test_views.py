from django.test import TestCase
from django.urls import reverse


class HomeViewTest(TestCase):
    """
    Test case for the home view in the passmanager app.
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
