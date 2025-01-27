<div align="center">
    <h1>
        <img src="static/images/logo.png" width="400" alt="Logo Icon"/>
    </h1>
    <p>Securely manage your passwords of your online accounts.<br><a href="https://passmanagerweb.onrender.com/">https://passmanagerweb.onrender.com/</a><br>Written in Python/Django</p>
    <h3>
        <a href="https://github.com/KafetzisThomas/PassManagerWeb">Homepage</a> |
        <a href="https://passmanagerweb.onrender.com/faq">FAQ</a> | 
        <a href="https://github.com/KafetzisThomas/PassManagerWeb/graphs/contributors">Contributors</a>
    </h3>
    <a href="https://github.com/KafetzisThomas/PassManagerWeb/actions/workflows/tests.yml">
        <img src = "https://github.com/KafetzisThomas/PassManagerWeb/actions/workflows/tests.yml/badge.svg" alt = 'Run Tests'/>
    </a>
</div>

---

## Features

- [X] **AES-128 Encryption**: Each user's data is encrypted using a **unique encryption key** derived from their `master password` and a user-specific `salt`, ensuring isolation between accounts.
- [X] **Multi-Factor Authentication**: Protect your account with your favorite authenticator app.
- [X] **Password Generator Tool**: Built-in tool to generate `strong`, `random` passwords, with `customizable` options (length, character types).
- [X] **Password Health Monitoring**: Built-in tool to check the strength and health of stored passwords, identifying `weak`, `reused`, or `compromised` passwords.
- [X] **Import/Export Data**: `Upload` data such as passwords from a CSV file or `download` your stored data in `CSV` format for easy backup or migration.
- [X] **Automatic Logout**: Automatically logs you out after a **customizable** period of inactivity. Choose the **timeout** duration that best suits your needs.
- [X] **Cloudflare CAPTCHA Verification**: Protects against automated attacks by using CAPTCHA to verify human users.

## Purpose

The primary goal of this project is to **provide an open-source application that anyone can use and learn from**. While the deployed app is available for use, my main intention is not to attract active users or compete with major applications like [Bitwarden](https://bitwarden.com/). Instead, I aim to share the code, primarily written in Django, with those who might find it useful for similar projects or personal use.

If you find this project interesting, helpful, or inspiring, please consider giving a `star`, `following`, or even `donating` to support further development.

## Setup for Local Development

### Set up Virtual Environment

```bash
➜ cd path/to/root/directory
$ python3 -m venv env/
$ source env/bin/activate
```

### Install Dependencies

```bash
$ pip3 install -r requirements.txt
```

### Create Enviroment Variable file

```bash
$ touch main/.env
$ nano main/.env
```

Add the following environment variables (modify as needed):
```bash
➜ SECRET_KEY="example_secret_key"  # https://stackoverflow.com/a/57678930
➜ DEBUG=True  # For development
➜ EMAIL_HOST_USER="example_email_host"
➜ EMAIL_HOST_PASSWORD="example_email_password"
```

Save changes and close the file.

### Migrate Database

```bash
$ python3 manage.py migrate
```

### Run Django Server
```bash
$ python3 manage.py runserver
```

Now you can access the website at `http://127.0.0.1:8000/` or `http://localhost:8000/`.

## Run Tests

```bash
➜ cd path/to/root/directory
$ python3 manage.py test users.tests passmanager.tests
```

## Demo Images

<div align = 'center'>
    <h2>Vault</h2>
    <img src='static/images/vault_page.png' alt='Vault'>
    <br><h2>Password Generator</h2>
    <img src='static/images/password_generator_page.png' alt='Password Generator'>
    <br><h2>Import Data</h2>
    <img src='static/images/import_data_page.png' alt='Import Data'>
    <br><h2>Password Checkup</h2>
    <img src = 'static/images/password_checkup_page.png' alt='Password Checkup'>
    <br><h2>Account Settings</h2>
    <img src='static/images/account_page.png' alt='Account Settings'>
    <br><h2>New Item</h2>
    <img src='static/images/new_item_page.png' alt='New Item'>
    <br><h2>Edit Item</h2>
    <img src='static/images/edit_item_page.png' alt='Edit Item'><br>
</div>

## Contributing Guidelines for PassManager

### Pull Requests
* **Simplicity**: Keep changes focused and easy to review.
* **Libraries**: Avoid adding non-standard libraries unless discussed via an issue.
* **Testing**: Ensure code runs error-free, passes all tests, and meets coding standards.

### Bug Reports
* Report bugs via GitHub Issues.
* Submit pull requests via GitHub Pull Requests.

Thank you for supporting PassManager!
