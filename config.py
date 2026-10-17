"""
Configuration module – loads settings from environment variables.
Supports .env files via python-dotenv.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    # Never generated at random: a random key changes on every restart/worker and logs everyone out.
    # get_config() refuses to start in production without it.
    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    # Session cookie hardening (SESSION_COOKIE_SECURE is switched on in ProductionConfig)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False
    SESSION_LIFETIME_HOURS = 8

    # Upload / request size limit (16 MB)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # Checkout limits
    MAX_QTY_PER_ITEM = int(os.environ.get('MAX_QTY_PER_ITEM', '50'))
    MAX_CART_LINES = 50

    # Turso / libSQL
    TURSO_DB_URL = os.environ.get('TURSO_DB_URL', '')
    TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '')

    # Cloudinary
    CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME', '')
    CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY', '')
    CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET', '')

    # Image settings
    MAX_IMAGE_WIDTH = 800
    MAX_IMAGE_HEIGHT = 800
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # App
    DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'


class DevelopmentConfig(Config):
    """Local development – falls back to local SQLite if no Turso URL."""
    DEBUG = True
    # If TURSO_DB_URL is not set, use local SQLite file
    USE_LOCAL_SQLITE = not Config.TURSO_DB_URL


class ProductionConfig(Config):
    """Production on Render."""
    DEBUG = False
    USE_LOCAL_SQLITE = False
    SESSION_COOKIE_SECURE = True   # cookies only over HTTPS (Render serves HTTPS)


def get_config():
    """Return the appropriate config based on FLASK_ENV."""
    env = os.environ.get('FLASK_ENV', 'development')
    if env == 'production':
        cfg = ProductionConfig()
        if len(cfg.SECRET_KEY) < 16:
            raise RuntimeError(
                "SECRET_KEY environment variable must be set (at least 16 characters) in production. "
                "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\"")
        return cfg
    cfg = DevelopmentConfig()
    if not cfg.SECRET_KEY:
        # Stable (not random) so local sessions survive reloads. Development only.
        cfg.SECRET_KEY = 'dev-only-insecure-key-do-not-use-in-production'
    return cfg
