import string
import secrets
import pwnedpasswords


def check_password(password):
    return pwnedpasswords.check(password, plain_text=True)


def generate_password(length, include_letters, include_digits, include_special_chars):
    """
    Return a random password string based on the provided options.
    """
    letters, digits, special_chars = (
        string.ascii_letters,
        string.digits,
        string.punctuation,
    )

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
