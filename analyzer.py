import re
import math


COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "abc123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "master"
}


SEQUENTIAL_PATTERNS = [
    "123456",
    "234567",
    "345678",
    "456789",
    "abcdef",
    "bcdefg",
    "cdefgh",
    "qwerty",
    "asdfgh",
    "zxcvbn"
]


def calculate_entropy(password):

    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26

    if any(c.isupper() for c in password):
        charset_size += 26

    if any(c.isdigit() for c in password):
        charset_size += 10

    if any(not c.isalnum() for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)

    return round(entropy, 2)


def analyze_password(password):

    score = 0
    suggestions = []
    checks = []

    # -------------------------
    # LENGTH
    # -------------------------

    if len(password) >= 12:

        score += 2

        checks.append({
            "name": "At least 12 characters",
            "passed": True
        })

    else:

        checks.append({
            "name": "At least 12 characters",
            "passed": False
        })

        suggestions.append(
            "Use at least 12 characters for better security."
        )


    # -------------------------
    # LOWERCASE
    # -------------------------

    has_lowercase = bool(re.search(r"[a-z]", password))

    if has_lowercase:

        score += 1

    else:

        suggestions.append(
            "Add lowercase letters."
        )

    checks.append({
        "name": "Lowercase letters",
        "passed": has_lowercase
    })


    # -------------------------
    # UPPERCASE
    # -------------------------

    has_uppercase = bool(re.search(r"[A-Z]", password))

    if has_uppercase:

        score += 1

    else:

        suggestions.append(
            "Add uppercase letters."
        )

    checks.append({
        "name": "Uppercase letters",
        "passed": has_uppercase
    })


    # -------------------------
    # NUMBERS
    # -------------------------

    has_number = bool(re.search(r"[0-9]", password))

    if has_number:

        score += 1

    else:

        suggestions.append(
            "Add numbers."
        )

    checks.append({
        "name": "Numbers",
        "passed": has_number
    })


    # -------------------------
    # SPECIAL CHARACTERS
    # -------------------------

    has_special = bool(
        re.search(r"[^A-Za-z0-9]", password)
    )

    if has_special:

        score += 1

    else:

        suggestions.append(
            "Add special characters such as !, @, # or $."
        )

    checks.append({
        "name": "Special characters",
        "passed": has_special
    })


    # -------------------------
    # COMMON PASSWORD
    # -------------------------

    is_common = password.lower() in COMMON_PASSWORDS

    checks.append({
        "name": "Not a common password",
        "passed": not is_common
    })

    if is_common:

        score = 0

        suggestions.append(
            "This is a commonly used password. "
            "Choose a unique password."
        )


    # -------------------------
    # SEQUENTIAL PATTERNS
    # -------------------------

    password_lower = password.lower()

    has_sequence = False

    for pattern in SEQUENTIAL_PATTERNS:

        if pattern in password_lower:

            has_sequence = True
            break


    checks.append({
        "name": "No predictable sequences",
        "passed": not has_sequence
    })


    if has_sequence:

        score -= 1

        suggestions.append(
            "Avoid predictable sequences such as "
            "123456, abcdef or qwerty."
        )


    # -------------------------
    # REPEATED CHARACTERS
    # -------------------------

    has_repetition = bool(
        re.search(r"(.)\1\1", password)
    )


    checks.append({
        "name": "No repeated characters",
        "passed": not has_repetition
    })


    if has_repetition:

        score -= 1

        suggestions.append(
            "Avoid repeating the same character multiple times."
        )


    # -------------------------
    # REPEATED PATTERNS
    # -------------------------

    has_repeated_pattern = bool(
        re.search(r"(.{2,})\1", password)
    )


    checks.append({
        "name": "No repeated patterns",
        "passed": not has_repeated_pattern
    })


    if has_repeated_pattern:

        score -= 1

        suggestions.append(
            "Avoid repeating patterns within the password."
        )


    # -------------------------
    # PREVENT NEGATIVE SCORE
    # -------------------------

    score = max(score, 0)


    # -------------------------
    # STRENGTH
    # -------------------------

    if score <= 2:

        strength = "Weak"

    elif score <= 4:

        strength = "Moderate"

    else:

        strength = "Strong"


    # -------------------------
    # ENTROPY
    # -------------------------

    entropy = calculate_entropy(password)


    return (
        score,
        strength,
        suggestions,
        entropy,
        checks
    )