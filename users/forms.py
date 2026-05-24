from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from .models import CustomUser
from zxcvbn import zxcvbn


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(label="Email Address",
        widget=forms.EmailInput(attrs={"autofocus": "autofocus", "class": "form-control"})
    )
    password1 = forms.CharField(label="Master Password", widget=forms.PasswordInput, required=True)
    password2 = forms.CharField(label="Confirm Master Password", widget=forms.PasswordInput, required=True)

    class Meta:
        model = CustomUser
        fields = ("email", "username")

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        if password:
            result = zxcvbn(password)
            if result["score"] < 3:  # 0 – 4 (=5 levels)
                raise forms.ValidationError("Password is too weak. Try adding more characters, numbers or symbols.")

        return password


class LoginForm(AuthenticationForm):
    username = forms.EmailField(label="Email Address",
        widget=forms.EmailInput(attrs={"autofocus": "autofocus", "class": "form-control"})
    )
    password = forms.CharField(label="Master Password", widget=forms.PasswordInput)


class EmailUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ("email",)


class UsernameUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ("username",)


class SessionTimeoutUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ("session_timeout",)
        labels = {
            'session_timeout': '',
        }
        widgets = {
            'session_timeout': forms.Select(attrs={'onchange': 'this.form.submit();'})
        }


class TwoFactorToggleForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ("enable_2fa",)
        widgets = {
            'enable_2fa': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'role': 'switch',
                'onchange': 'this.form.submit();'
            })
        }


class TwoFactorVerificationForm(forms.Form):
    otp = forms.CharField(label="Generated OTP",
        widget=forms.TextInput(attrs={"autofocus": "autofocus", "class": "form-control"})
    )


class MasterPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(label="Old Master Password",
        widget=forms.PasswordInput(attrs={"autofocus": "autofocus", "class": "form-control"})
    )
    new_password1 = forms.CharField(label="New Master Password", widget=forms.PasswordInput)
    new_password2 = forms.CharField(label="Confirm New Master Password", widget=forms.PasswordInput)

    def clean_new_password1(self):
        password = self.cleaned_data.get("new_password1")
        if password:
            result = zxcvbn(password)
            if result["score"] < 3:  # 0 – 4 (=5 levels)
                raise forms.ValidationError("Password is too weak. Try adding more characters, numbers or symbols.")

        return password


class PasswordConfirmationForm(forms.Form):
    password = forms.CharField(label="Confirm Master Password", required=True,
        widget=forms.PasswordInput(attrs={"autofocus": "autofocus", "class": "form-control"})
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get("password")
        if not self.user:
            raise forms.ValidationError("No user provided.")
        if not self.user.check_password(password):
            raise forms.ValidationError("Incorrect master password.")
        return password
