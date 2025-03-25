import pyotp
from django.contrib.auth import get_user_model
from .models import CustomUser
from django import forms
from django.contrib.auth.forms import (
    UserCreationForm,
    AuthenticationForm,
    PasswordChangeForm,
)


class CustomUserCreationForm(UserCreationForm):
    password1 = forms.CharField(
        label="Master Password", widget=forms.PasswordInput, required=True
    )
    password2 = forms.CharField(
        label="Confirm Master Password", widget=forms.PasswordInput, required=True
    )

    class Meta:
        model = CustomUser
        fields = ("email", "username", "password1", "password2")

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

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("username")
        password = cleaned_data.get("password")
        User = get_user_model()

        user = User.objects.get(email=email)
        if not user or not user.check_password(password):
            raise forms.ValidationError("Invalid email or password.")

        self.cleaned_data["user"] = user
        return cleaned_data


class TwoFactorVerificationForm(forms.Form):
    otp = forms.CharField(label="Generated OTP", widget=forms.TextInput)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

    def clean(self):
        otp = self.cleaned_data.get("otp")
        if not self.user or not self.user.otp_secret:
            raise forms.ValidationError("Invalid user or OTP configuration.")

        totp = pyotp.TOTP(self.user.otp_secret)
        if not totp.verify(otp):
            raise forms.ValidationError("Invalid OTP.")

        return self.cleaned_data


class CustomUserChangeForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = (
            "email",
            "username",
            "session_timeout",
            "enable_2fa",
            "allow_account_update_notifications",
            "allow_master_password_update_notifications",
        )


class MasterPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Old Master Password", widget=forms.PasswordInput
    )
    new_password1 = forms.CharField(
        label="New Master Password", widget=forms.PasswordInput
    )
    new_password2 = forms.CharField(
        label="Confirm New Master Password", widget=forms.PasswordInput
    )


class PasswordConfirmationForm(forms.Form):
    password = forms.CharField(
        label="Confirm Master Password",
        widget=forms.PasswordInput(),
        required=True,
    )
