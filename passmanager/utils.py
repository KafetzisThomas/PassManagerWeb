import hashlib
import secrets
import string
import requests


def check_pwned_password(password: str) -> int:
    """
    Check if the given password has been pwned using the HIBP API.
    """
    # SHA1 hash of the password
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # Query the HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    response.raise_for_status()

    # Check if suffix is in the response
    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0


def generate_password(length: int, include_letters: bool, include_digits: bool, include_special_chars: bool) -> str:
    """
    Return a random password string based on the provided options.
    """
    letters, digits, special_chars = (string.ascii_letters, string.digits, string.punctuation)
    selected_chars = []
    if include_letters:
        selected_chars.append(letters)
    if include_digits:
        selected_chars.append(digits)
    if include_special_chars:
        selected_chars.append(special_chars)
    alphabet = "".join(selected_chars)

    password = ""
    for _ in range(int(length)):
        password += "".join(secrets.choice(alphabet))

    return password
