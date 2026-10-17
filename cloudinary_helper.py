"""
Cloudinary helper – handles image upload, deletion, and URL generation.
Replaces the local static/uploads/ workflow.
"""
try:
    import cloudinary
    import cloudinary.uploader
    import cloudinary.api
    HAS_CLOUDINARY = True
except ImportError:
    HAS_CLOUDINARY = False

from config import get_config

_config = get_config()

# ---------------------------------------------------------------------------
# Initialise Cloudinary SDK
# ---------------------------------------------------------------------------
if HAS_CLOUDINARY:
    cloudinary.config(
        cloud_name=_config.CLOUDINARY_CLOUD_NAME,
        api_key=_config.CLOUDINARY_API_KEY,
        api_secret=_config.CLOUDINARY_API_SECRET,
        secure=True
    )


def _is_configured() -> bool:
    """Return True if Cloudinary credentials and SDK are present."""
    return bool(
        HAS_CLOUDINARY
        and _config.CLOUDINARY_CLOUD_NAME
        and _config.CLOUDINARY_API_KEY
        and _config.CLOUDINARY_API_SECRET
    )


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
def upload_image(file, folder: str = "products", max_width: int = 800,
                 max_height: int = 800) -> str | None:
    """
    Upload an image file to Cloudinary at original quality.

    Transformations (quality, format, resize) are intentionally NOT applied
    at upload time — they are applied at delivery time via get_optimized_url()
    so the stored master copy retains full fidelity.

    Args:
        file: A file-like object (from request.files).
        folder: Cloudinary folder path (e.g. 'products' or 'branding').
        max_width: Unused; kept for backwards-compatible call signatures.
        max_height: Unused; kept for backwards-compatible call signatures.

    Returns:
        The secure URL string, or None on failure.
    """
    if not _is_configured():
        return None

    if not file or not hasattr(file, 'filename') or not file.filename:
        return None

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in _config.ALLOWED_EXTENSIONS:
        return None

    try:
        # Store the original at full quality; let delivery-time transforms handle
        # resizing and compression so clarity is never permanently reduced.
        result = cloudinary.uploader.upload(
            file,
            folder=folder,
            resource_type="image",
            overwrite=False,
            unique_filename=True,
        )
        return result.get('secure_url')
    except Exception as e:
        print(f"[Cloudinary] Upload error: {e}")
        return None


def upload_logo(file, folder: str = "branding") -> str | None:
    """
    Upload a shop logo with transparency preservation at original quality.

    Transformations are applied at delivery time (not upload time) to
    preserve full image fidelity in the stored master copy.
    """
    if not _is_configured():
        return None

    if not file or not hasattr(file, 'filename') or not file.filename:
        return None

    try:
        # Store original; delivery-time transforms (via get_optimized_url) handle
        # quality/format. PNG transparency is preserved in the master copy.
        result = cloudinary.uploader.upload(
            file,
            folder=folder,
            resource_type="image",
            overwrite=False,
            unique_filename=True,
        )
        return result.get('secure_url')
    except Exception as e:
        print(f"[Cloudinary] Logo upload error: {e}")
        return None


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------
def delete_image(url: str) -> bool:
    """
    Delete an image from Cloudinary by its URL.

    Extracts the public_id from the URL and calls destroy().
    Returns True on success.
    """
    if not _is_configured() or not url:
        return False

    try:
        # Extract public_id from URL
        # URL format: https://res.cloudinary.com/<cloud>/image/upload/v123/folder/filename.ext
        parts = url.split('/upload/')
        if len(parts) < 2:
            return False
        path_with_version = parts[1]
        # Remove version prefix (v123456789/)
        if path_with_version.startswith('v') and '/' in path_with_version:
            path = path_with_version.split('/', 1)[1]
        else:
            path = path_with_version
        # Remove file extension
        public_id = path.rsplit('.', 1)[0]

        result = cloudinary.uploader.destroy(public_id)
        return result.get('result') == 'ok'
    except Exception as e:
        print(f"[Cloudinary] Delete error: {e}")
        return False


# ---------------------------------------------------------------------------
# Optimised delivery URL
# ---------------------------------------------------------------------------
def get_optimized_url(url: str, width: int = None, height: int = None,
                      quality: str = "auto:best") -> str:
    """
    Return a Cloudinary delivery URL with format/quality/resize transformations.

    Because we now store originals at full quality, this is the ONLY place
    where compression and resizing happen — ensuring on-screen images are
    crisp while bandwidth is still managed efficiently.

    Args:
        url: The Cloudinary secure_url from the database.
        width: Optional display width to resize to (e.g. 800).
        height: Optional display height to resize to (e.g. 800).
        quality: Cloudinary quality string. Defaults to 'auto:best' for
                 maximum sharpness. Use 'auto:good' for lighter pages.
    """
    if not url or 'cloudinary' not in url:
        return url or ''

    if '/upload/' not in url:
        return url

    # Build transformation string
    transforms = [f"f_auto", f"q_{quality}"]
    if width and height:
        transforms.append(f"w_{width},h_{height},c_limit")
    elif width:
        transforms.append(f"w_{width},c_limit")
    elif height:
        transforms.append(f"h_{height},c_limit")

    transform_str = ",".join(transforms)
    return url.replace('/upload/', f'/upload/{transform_str}/')
