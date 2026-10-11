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
