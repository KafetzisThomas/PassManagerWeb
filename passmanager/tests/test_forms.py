from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from ..forms import ImportDataForm

User = get_user_model()

class ImportDataFormTests(TestCase):

    def test_valid_csv_file_import(self):
        csv_content = b"name,username,password,domain,notes\nExample name,example_user,example_pass,example.com,example notes"
        file = SimpleUploadedFile("test.csv", csv_content, content_type="text/csv")
        form = ImportDataForm(data={}, files={"csv_file": file})
        self.assertTrue(form.is_valid(), form.errors)

    def test_invalid_file_extension(self):
        csv_content = b"Dummy content"
        file = SimpleUploadedFile("test.txt", csv_content, content_type="text/plain")
        form = ImportDataForm(data={}, files={"csv_file": file})
        self.assertFalse(form.is_valid(), form.errors)
