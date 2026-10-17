"""
Password helpers.

New passwords are stored with Werkzeug's salted hashes (scrypt). Older accounts that were
stored as a plain SHA-256 hex digest keep working, and are upgraded to the new format
automatically the first time they log in successfully.
"""
import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash

_MODERN_PREFIXES = ('scrypt:', 'pbkdf2:')


def hash_password(password: str) -> str:
    """Return a salted hash suitable for storing."""
    return generate_password_hash(password)


def is_modern_hash(stored: str) -> bool:
    return (stored or '').strip().startswith(_MODERN_PREFIXES)


def needs_rehash(stored: str) -> bool:
    """True if the stored value is in a legacy format and should be upgraded."""
    return not is_modern_hash(stored)


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored value (modern hash, legacy SHA-256, or legacy plain text)."""
    stored = (stored or '').strip()
    if not stored:
        return False
    if is_modern_hash(stored):
        try:
            return check_password_hash(stored, password)
        except Exception:
            return False
    legacy_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if hmac.compare_digest(legacy_hash.lower(), stored.lower()):
        return True
    return hmac.compare_digest(password.encode('utf-8'), stored.encode('utf-8'))


_COMMON_PASSWORDS = {
    'admin123', 'master123', 'password', 'password1', 'password123', '12345678', '123456789',
    '1234567890', 'qwerty123', 'qwertyuiop', 'iloveyou', 'welcome123', 'abc12345', 'admin1234',
}
MIN_PASSWORD_LENGTH = 8


def validate_new_password(password: str, username: str = '') -> str:
    """Return an error message if the password is too weak, otherwise an empty string."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f'Password must be at least {MIN_PASSWORD_LENGTH} characters long.'
    if password.lower() in _COMMON_PASSWORDS:
        return 'That password is too common. Please choose a less predictable one.'
    if username and password.lower() == username.strip().lower():
        return 'Password must not be the same as the username.'
    if password.isdigit() or len(set(password)) < 3:
        return 'Password is too simple. Mix letters and numbers.'
    return ''
