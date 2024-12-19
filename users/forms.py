import pyotp
from turnstile.fields import TurnstileField
from django.contrib.auth import get_user_model
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import CustomUser
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password


class CustomUserCreationForm(UserCreationForm):
    password1 = forms.CharField(
        label="Master Password", widget=forms.PasswordInput, required=True
    )
    password2 = forms.CharField(
        label="Confirm Master Password", widget=forms.PasswordInput, required=True
    )
    captcha_verification = TurnstileField(theme="light", size="flexible")

    class Meta:
        model = CustomUser
        fields = ("email", "username", "password1", "password2", "captcha_verification")

    def clean(self):
        """
        Ensure that passwords are properly validated only when provided.
        """
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        # Validate password match
        if (password1 and password2) and (password1 != password2):
            self.add_error("password2", "The two password fields didn’t match.")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get("password1"):
            user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(label="Email Address", widget=forms.EmailInput)
    password = forms.CharField(label="Master Password", widget=forms.PasswordInput)
    otp = forms.CharField(label="Generated OTP", widget=forms.TextInput)

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("username")
        password = cleaned_data.get("password")
        otp = cleaned_data.get("otp")

        if email and password and otp:
            User = get_user_model()
            try:
                user = User.objects.get(email=email)
                totp = pyotp.TOTP(user.otp_secret)
                if not totp.verify(otp):
                    raise forms.ValidationError("Invalid OTP")
            except User.DoesNotExist:
                raise forms.ValidationError("Invalid email or password")

        return cleaned_data


class CustomUserChangeForm(forms.ModelForm):
    password1 = forms.CharField(
        label="New Master Password", widget=forms.PasswordInput, required=False
    )
    password2 = forms.CharField(
        label="Confirm New Master Password", widget=forms.PasswordInput, required=False
    )

    class Meta:
        model = CustomUser
        fields = ("email", "username", "password1", "password2")

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password1 != password2:
            self.add_error("password2", "Passwords do not match.")

        if password1:
            try:
                validate_password(password1)
            except ValidationError as e:
                self.add_error("password1", e)

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get("password1")
        if password:
            user.set_password(password)
        if commit:
            user.save()
        return user
