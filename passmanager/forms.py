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
        fields = ["name", "username", "password", "url", "notes", "group"]

    def __init__(self, *args, **kwargs):
        super(ItemForm, self).__init__(*args, **kwargs)
        self.fields["username"].required = False
        self.fields["password"].required = False
        self.fields["url"].required = False
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


class ImportPasswordsForm(forms.Form):
    csv_file = forms.FileField(
        label="Select CSV File",
        help_text="Import your CSV file with the following columns: name, username, password, url, notes.",
        widget=forms.ClearableFileInput(attrs={"accept": ".csv"}),
    )

    def clean(self):
        cleaned_data = super().clean()
        csv_file = cleaned_data.get("csv_file")

        # Check file extension
        if not csv_file.name.endswith(".csv"):
            raise forms.ValidationError("Invalid file type. Please import a CSV file.")

        return cleaned_data
