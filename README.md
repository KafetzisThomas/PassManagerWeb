<div align="center">
    <h1>
        <img src="passmanager/static/images/logo.png" width="400" alt="Logo Icon"/>
    </h1>
    <p>Securely manage your passwords of your online accounts.<br><a href="https://passmanagerweb.onrender.com/">https://passmanagerweb.onrender.com/</a><br>Written in Python/Django</p>
    <h3>
        <a href="https://github.com/PassManagerWeb/PassManagerWeb">Homepage</a> |
        <a href="https://passmanagerweb.onrender.com/faq">FAQ</a> | 
        <a href="https://github.com/PassManagerWeb/PassManagerWeb/graphs/contributors">Contributors</a>
    </h3>
    <a href="https://github.com/PassManagerWeb/PassManagerWeb/actions/workflows/tests.yml">
        <img src = "https://github.com/PassManagerWeb/PassManagerWeb/actions/workflows/tests.yml/badge.svg" alt = 'Run Tests'/>
    </a>
</div>

---

## Features

- [X] **AES 256 Encryption**: Securely store and manage passwords with AES 256-bit encryption, ensuring top-tier security for **sensitive information**.
- [X] **Multi-Factor Authentication**: Protect your account with your favorite authenticator app.
- [X] **Password Generator Tool**: Built-in tool to generate `strong`, `random` passwords, with `customizable` options (length, character types).
- [X] **Password Health Monitoring**: Built-in tool to check the strength and health of stored passwords, identifying `weak`, `reused`, or `compromised` passwords.
- [X] **Automatic Logout**: Enhanced security with automatic logout after **15 minutes** of inactivity or on **browser close**.
- [X] **Cloudflare CAPTCHA Verification**: Protects against automated attacks by using CAPTCHA to verify human users.
- [X] **Valid Email Domain Verification**: Ensures that only valid email domains are accepted during registration, **reducing the risk of spam and fraudulent accounts**.

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
➜ ENCRYPTION_KEY="example_encryption_key"  # https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet
➜ DEBUG=True  # For development
# Optional, required if email features are used
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

## Screenshots

<div align = 'center'>
    <h2>Vault</h2>
    <img src = 'https://github.com/PassManagerWeb/PassManagerWeb/assets/105563667/2babd158-ec4f-496c-acdc-707022a0e252' alt = 'Vault'>
    <br>
    <h2>Password Generator</h2>
    <img src = 'https://github.com/PassManagerWeb/PassManagerWeb/assets/105563667/2a4f2ed8-23aa-4d32-9516-1a22c097c00f' alt = 'Password Generator'>
    <br>
    <h2>Add Item</h2>
    <img src = 'https://github.com/PassManagerWeb/PassManagerWeb/assets/105563667/d2e3d7e5-8ade-46b1-a9c3-3ae025f7aa44' alt = 'New Item'>
    <br>
</div>

## Contributing Guidelines for PassManager

### Pull Requests
When submitting a pull request, please keep these points in mind:

* **Simplicity**: Keep your changes straightforward and focused. Complex changes are harder to review and integrate.

* **Avoid Non-Standard Libraries**: Whenever possible, refrain from adding new non-standard libraries. If your idea necessitates one, kindly discuss it first by opening an issue. This helps in evaluating the necessity and compatibility of the library.

* **Ensure It Runs**: Before submitting a pull request, ensure that your code runs without errors and adheres to the project's coding standards.

* **Pass All Tests**: Make sure all existing [tests](#run-tests) pass and add new tests as necessary. Pull requests will not be merged unless all tests pass successfully.

### Filing Bug Reports and Submitting Pull Requests
If you encounter a bug, please follow these steps to report it:

* **Bug Reports**: File bug reports on the [GitHub Issues](https://github.com/PassManagerWeb/PassManagerWeb/issues) page.
* **Pull Requests**: Open pull requests on the [GitHub Pull Requests](https://github.com/PassManagerWeb/PassManagerWeb/pulls) page.

Before contributing, please review the [License](https://github.com/PassManagerWeb/PassManagerWeb/blob/main/LICENSE) to understand the terms and conditions governing the use and distribution of PassManager.

Thank you for your interest in improving PassManager!
