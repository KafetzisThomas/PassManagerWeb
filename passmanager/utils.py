import hashlib
import requests

def check_pwned_password(password: str) -> int:
    """
    Check if the given password has been pwned using the HIBP API.
    """
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    response.raise_for_status()

    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0
