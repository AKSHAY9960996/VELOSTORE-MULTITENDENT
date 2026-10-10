"""
Configuration module – loads settings from environment variables.
Supports .env files via python-dotenv.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())

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


def get_config():
    """Return the appropriate config based on FLASK_ENV."""
    env = os.environ.get('FLASK_ENV', 'development')
    if env == 'production':
        return ProductionConfig()
    return DevelopmentConfig()
