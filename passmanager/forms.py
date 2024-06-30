from django import forms
from .models import Item


class ItemForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(
            render_value=True,
        )
    )

    class Meta:
        model = Item
        fields = ["name", "website", "username", "password", "notes"]

    def __init__(self, *args, **kwargs):
        super(ItemForm, self).__init__(*args, **kwargs)
        self.fields["website"].required = False
        self.fields["username"].required = False
        self.fields["password"].required = False
        self.fields["notes"].required = False


class PasswordGeneratorForm(forms.Form):
    length = forms.IntegerField(
        label="Length",
        min_value=8,
        max_value=32,
        initial=12,
        widget=forms.NumberInput(
            attrs={"class": "form-control form-control-lg lengthfield-size"}
        ),
    )
    letters = forms.BooleanField(
        label="A-Z/a-z",
        initial=True,
        required=True,
        widget=forms.CheckboxInput(
            attrs={"class": "form-check-input", "disabled": True}
        ),
    )
    digits = forms.BooleanField(
        label="0-9",
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    special_chars = forms.BooleanField(
        label="!@#$%^&*",
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
