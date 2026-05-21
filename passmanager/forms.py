from django import forms
from .models import Item


class ItemForm(forms.ModelForm):
    username = forms.CharField(required=False, widget=forms.TextInput())
    password = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'id_password'}))
    url = forms.URLField(required=False)

    class Meta:
        model = Item
        fields = ["name", "username", "password", "url", "notes"]


class ImportPasswordsForm(forms.Form):
    csv_file = forms.FileField(
        label="Select CSV File",
        help_text="Import your CSV file with the following columns: name, username, password, url, notes.",
        widget=forms.ClearableFileInput(attrs={"accept": ".csv"}),
    )

    def clean_csv_file(self):
        file = self.cleaned_data["csv_file"]
        if not file.name.lower().endswith(".csv"):
            raise forms.ValidationError("Invalid file type, please import a csv file.")
        return file
