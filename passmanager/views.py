import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import TemplateView, FormView
from dotenv import load_dotenv

from .decorators import reauth_required
from .forms import ItemForm, PasswordGeneratorForm, ImportPasswordsForm
from .models import Item
from .utils import check_pwned_password, generate_password

load_dotenv()


class VaultView(LoginRequiredMixin, TemplateView):
    template_name = "passmanager/vault.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Retrieve selected group & search query from the query parameters
        selected_group = self.request.GET.get("group")
        search_query = self.request.GET.get("search_query")

        items = Item.objects.filter(owner=user).order_by("name")
        groups = (Item.objects.filter(owner=user).values_list("group", flat=True).distinct())

        if selected_group:
            items = items.filter(group=selected_group)

        if search_query:
            items = items.filter(name__icontains=search_query)

        context.update({"items": items, "groups": groups,
                        "selected_group": selected_group, "search_query": search_query})

        return context


class NewItemView(LoginRequiredMixin, FormView):
    template_name = "passmanager/new_item.html"
    form_class = ItemForm
    success_url = reverse_lazy("passmanager:vault")

    def form_valid(self, form):
        action = self.request.POST.get("action", "value")
        user = self.request.user

        if action == "save":
            obj = form.save(commit=False)
            obj.owner = user
            obj.encrypt_sensitive_fields()
            obj.save()
            messages.success(self.request, "Item created successfully.")
            return super().form_valid(form)

        elif action == "generate_password":
            generated_password = generate_password(length=12, include_letters=True,
                                                   include_digits=True, include_special_chars=True)

            # Create a mutable copy of POST data to update password
            mutable_post_data = self.request.POST.copy()
            mutable_post_data["password"] = generated_password

            # Create a new form with updated data
            form = self.form_class(data=mutable_post_data)

            # Update the form's initial data for rendering
            form.initial["username"] = form.data.get("username", "")
            form.initial["password"] = generated_password
            form.initial["notes"] = form.data.get("notes", "")

            messages.success(self.request, "New password has been generated successfully.")

            # Instead of redirecting, re-render the form with updated password
            return self.render_to_response(self.get_context_data(form=form))

        # Fallback, just render form again
        return self.render_to_response(self.get_context_data(form=form))

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the errors below.")
        return super().form_invalid(form)


class EditItemView(LoginRequiredMixin, View):
    template_name = "passmanager/edit_item.html"
    form_class = ItemForm

    def get_object(self):
        item = get_object_or_404(Item, id=self.kwargs.get("item_id"))
        if item.owner != self.request.user:
            raise Http404
        return item

    def get(self, request, *args, **kwargs):
        item = self.get_object()
        item.decrypt_sensitive_fields()
        form = self.form_class(instance=item)
        return render(request, self.template_name, {"item": item, "form": form})

    def post(self, request, *args, **kwargs):
        item = self.get_object()
        action = request.POST.get("action")

        if action == "delete":
            item.delete()
            messages.success(request, "Item deleted successfully.")
            return redirect("passmanager:vault")

        form = self.form_class(instance=item, data=request.POST)

        if form.is_valid():
            obj = form.save(commit=False)
            username_entry = obj.username
            notes_entry = obj.notes

            if action == "save":
                obj.owner = request.user
                obj.encrypt_sensitive_fields()
                obj.save()
                messages.success(request, "Item modified successfully.")
                return redirect("passmanager:vault")

            elif action == "generate_password":
                generated_password = generate_password(
                    length=12,
                    include_letters=True,
                    include_digits=True,
                    include_special_chars=True,
                )

                # Re-initialize form with generated password
                form = self.form_class(instance=item)
                form.initial["username"] = username_entry
                form.initial["password"] = generated_password
                form.initial["notes"] = notes_entry

                messages.success(request, "New password has been generated successfully.")
                return render(request, self.template_name, {"item": item, "form": form})

        # If form is invalid
        messages.error(request, "The item could not be changed because the data didn't validate.")
        return render(request, self.template_name, {"item": item, "form": form})


@login_required
def password_generator(request):
    form = PasswordGeneratorForm()
    password = ""  # Initialize password variable

    if request.method == "POST":
        form = PasswordGeneratorForm(request.POST)
        if form.is_valid():
            length = form.cleaned_data["length"]
            include_letters = form.cleaned_data["letters"]
            include_digits = form.cleaned_data["digits"]
            include_special_chars = form.cleaned_data["special_chars"]
            password = generate_password(
                length, include_letters, include_digits, include_special_chars
            )

    context = {"form": form, "password": password}
    return render(request, "passmanager/password_generator.html", context)

@login_required
@reauth_required
def export_csv(request):
    # Create response with csv content type & set filename for download
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="PassManager Passwords.csv"'
    writer = csv.writer(response)

    # Write csv header (column names)
    writer.writerow(["name", "username", "password", "url", "notes", "group"])

    # Fetch user-specific data
    data = Item.objects.filter(owner=request.user)

    for item in data:
        item.decrypt_sensitive_fields()
        writer.writerow(
            [item.name, item.username, item.password, item.url, item.notes, item.group]
        )

    return response

@login_required
def import_csv(request):
    if request.method == "POST":
        form = ImportPasswordsForm(request.POST, request.FILES)
        if form.is_valid():
            # Read the uploaded file
            csv_file = form.cleaned_data["csv_file"]
            file_data = csv_file.read().decode("utf-8").splitlines()
            csv_reader = csv.reader(file_data)

            # Skip the header row
            header = next(csv_reader)
            expected_header = ["name", "username", "password", "url", "notes", "group"]

            if header != expected_header:
                messages.error(
                    request, "Invalid CSV format. Please check the column names."
                )
                return redirect("passmanager:import_csv")

            for row in csv_reader:
                name, username, password, url, notes, group = row
                item = Item(
                    name=name,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes,
                    group=group,
                    owner=request.user,
                )
                item.encrypt_sensitive_fields()
                item.save()

            messages.success(request, "Passwords imported successfully!")
            return redirect("passmanager:vault")
    else:
        form = ImportPasswordsForm()

    return render(request, "passmanager/import_csv.html", {"form": form})

@login_required
def password_checkup(request):
    items = Item.objects.filter(owner=request.user)
    results = []
    for item in items:
        item.decrypt_sensitive_fields()
        password_status = check_pwned_password(item.password) if item.password else None
        if password_status:
            results.append(
                {
                    "name": item.name,
                    "status": f"Exposed {password_status} time(s)",
                    "recommendation": "Changing this password is recommended.",
                    "severity": "High",
                }
            )
        else:
            results.append(
                {
                    "name": item.name,
                    "status": "No breaches found.",
                    "recommendation": "This password appears to be safe.",
                    "severity": "Low",
                }
            )

    return render(request, "passmanager/password_checkup.html", {"results": results})
