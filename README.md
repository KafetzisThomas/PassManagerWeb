<div align="center">
    <img src="passmanager/static/images/logo.png" width="400" alt="Logo Icon"/><br><br>
    <p>Self-hosted password manager for secure online credentials.<br>Written in Python/Django</p>
    <img src="https://github.com/KafetzisThomas/PassManagerWeb/actions/workflows/tests.yml/badge.svg" alt="Run Tests"/>
    <img src="https://img.shields.io/badge/Docker-Enabled-blue?logo=docker" alt="Docker Enabled"/>
</div>

## Features

- [X] **AES-256 GCM Encryption**: Each user's data is encrypted using a **unique encryption key** derived from their `master password` and a user-specific `salt`, ensuring isolation between accounts.
- [X] **Multi-Factor Authentication**: Protect your account with your favorite authenticator app.
- [X] **Password Generator Tool**: Built-in tool to generate `strong`, `random` passwords, with `customizable` options (length, character types).
- [X] **Password Health Monitoring**: Built-in tool to check the strength and health of stored passwords, identifying `weak`, `reused`, or `compromised` passwords.
- [X] **Import/Export Data**: `Upload` data such as passwords from a CSV file or `download` your stored data in `CSV` format for easy backup or migration.
- [X] **Automatic Logout**: Automatically logs you out after a **customizable** period of inactivity. Choose the **timeout** duration that best suits your needs.

## Purpose

The primary goal of this project is to **provide a self-hostable,  open-source password manager that anyone can use and learn from**.
While the app is available for use, my main intention is not to attract active users or compete with major applications like [Bitwarden](https://bitwarden.com/).
Instead, I aim to offer a self-host option for those who prefer full control over their password management and to share the code, primarily written in Django, for educational or personal use.

If you find this project interesting, helpful, or inspiring, please consider giving a `star`, `following`, or even `donating` to support further development.

## Setup for Local Development

### Install uv

```bash
cd path/to/root/directory
pip install uv
```

### Create Environment Variable file

```bash
touch main/.env
nano main/.env
```

Add the following (adjust as needed):

```ini
# Django settings
SECRET_KEY="example_secret_key"  # https://stackoverflow.com/a/57678930
ALLOWED_HOSTS="localhost,127.0.0.1"
CSRF_TRUSTED_ORIGINS="http://localhost:8001"
DEBUG=True  # For development

# OPTIONAL: PostgreSQL Configuration (remote production)
DATABASE_URL="postgres://[username]:[password]@[host]:[port]/[db_name]"

# Email settings
EMAIL_HOST_USER="example_email_host"
EMAIL_HOST_PASSWORD="example_email_password"
```

Save changes and close the file.

> **Note:** You can deploy the application using Docker:  
> **NGINX + Gunicorn + External DB**  
>
> ```bash
> docker compose up
> ```

### Migrate Database

```bash
uv run manage.py migrate
```

### Run Django Server

```bash
uv run manage.py runserver
```

Access web application at `http://127.0.0.1:8000` or `http://localhost:8000`.

## Run Tests

```bash
uv run manage.py test
```

## Demo Images

![Vault](passmanager/static/images/vault_page.png)

![Password Generator](passmanager/static/images/password_generator_page.png)

![Import Data](passmanager/static/images/import_data_page.png)

![Password Checkup](passmanager/static/images/password_checkup_page.png)

![Account Settings](passmanager/static/images/account_page.png)

![New Item](passmanager/static/images/new_item_page.png)

![Edit Item](passmanager/static/images/edit_item_page.png)

## Contributing Guidelines

### Pull Requests

- **Simplicity**: Keep changes focused and easy to review.
- **Libraries**: Avoid adding non-standard libraries unless discussed via an issue.
- **Testing**: Ensure code runs error-free, passes all tests, and meets coding standards.

### Bug Reports

- Report bugs via GitHub Issues.
- Submit pull requests via GitHub Pull Requests.

Thank you for supporting PassManager!
