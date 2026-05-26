from django.test import TestCase
from django.contrib.auth import get_user_model
from ..forms import RegistrationForm, LoginForm, MasterPasswordChangeForm, PasswordConfirmationForm

User = get_user_model()


class RegistrationFormTests(TestCase):

    def setUp(self):
        self.password_strength_weak = {
            "email": "user@test.com",
            "username": "user",
            "password1": "password123",
            "password2": "password123"
        }
        self.password_strength_strong = {
            "email": "user@test.com",
            "username": "user",
            "password1": "Str0ng_p@ssword",
            "password2": "Str0ng_p@ssword"
        }

    def test_password_strength_validation_weak(self):
        form = RegistrationForm(data=self.password_strength_weak)
        self.assertFalse(form.is_valid())

    def test_password_strength_validation_strong(self):
        form = RegistrationForm(data=self.password_strength_strong)
        self.assertTrue(form.is_valid(), form.errors)


class LoginFormTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")

    def test_form_valid_data(self):
        form_data = {
            "username": "user@test.com",
            "password": "Str0ng_p@ssword"
        }
        form = LoginForm(data=form_data)        
        self.assertTrue(form.is_valid(), form.errors)

    def test_enforces_email_format_for_username(self):
        form_data = {
            "username": "username_intead_of_email",
            "password": "Str0ng_p@ssword"
        }
        form = LoginForm(data=form_data)
        self.assertFalse(form.is_valid(), form.errors)


class MasterPasswordChangeFormTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")
        self.master_password_weak = {
            "old_password": "Str0ng_p@ssword",
            "new_password1": "password123",
            "new_password2": "password123"
        }
        self.master_password_strong = {
            "old_password": "Str0ng_p@ssword",
            "new_password1": "New_Str0ng_p@ssword",
            "new_password2": "New_Str0ng_p@ssword"
        }

    def test_master_password_change_weak(self):
        form = MasterPasswordChangeForm(user=self.user, data=self.master_password_weak)
        self.assertFalse(form.is_valid(), form.errors)

    def test_master_password_change_strong(self):
        form = MasterPasswordChangeForm(user=self.user, data=self.master_password_strong)
        self.assertTrue(form.is_valid(), form.errors)


class PasswordConfirmationFormTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(email="user@test.com", username="user", password="Str0ng_p@ssword")

    def test_password_confirmation_valid(self):
        form = PasswordConfirmationForm(user=self.user, data={"password": "Str0ng_p@ssword"})
        self.assertTrue(form.is_valid(), form.errors)

    def test_password_confirmation_invalid(self):
        form = PasswordConfirmationForm(user=self.user, data={"password": "password123"})
        self.assertFalse(form.is_valid(), form.errors)
