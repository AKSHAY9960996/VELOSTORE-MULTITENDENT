"""Core of the app: Flask app, multi-tenant middleware, database helpers, uploads, auth helpers and error pages.

Routes live in routes_storefront.py, routes_admin.py and routes_master.py.
"""
import os
import json
import csv
import io
import hashlib
import secrets
from datetime import datetime, timedelta
import urllib.parse
from functools import wraps
from flask import (Flask, render_template, render_template_string, request, redirect, url_for,
                   session, flash, jsonify, g, Response)
from config import get_config, ProductionConfig
from security import hash_password, verify_password, needs_rehash
from db import (Database, get_connection, is_turso, init_master_db,
                get_master_db_connection, get_tenant_by_identifier,
                get_tenant_db_connection, provision_new_tenant,
                get_tenant_feature_flags, update_tenant_admin_password,
                delete_tenant, DEFAULT_PLAN_CONFIG, clear_tenant_cache)
import cloudinary_helper

# ---------------------------------------------------------------------------
# App Configuration & Multi-Tenant Setup
# ---------------------------------------------------------------------------
app_config = get_config()

app = Flask(__name__)

app.secret_key = app_config.SECRET_KEY

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

ALLOWED_EXTENSIONS = app_config.ALLOWED_EXTENSIONS

# On Render the disk is wiped at every deploy, so images must never be stored locally in production.
# Local fallback to static/uploads/ is only allowed during local development.
LOCAL_UPLOADS_ALLOWED = not isinstance(app_config, ProductionConfig)

if not LOCAL_UPLOADS_ALLOWED and not cloudinary_helper._is_configured():
    print('[Config] WARNING: Cloudinary is not configured. Image uploads will be rejected '
          '(set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET).', flush=True)

_master_db_initialized = False

def _ensure_master_db_ready():
    global _master_db_initialized
    if not _master_db_initialized:
        try:
            init_master_db()
            _master_db_initialized = True
        except Exception as e:
            print(f"[Init] Master DB lazy init error: {e}")

_default_db_initialized = False

def _ensure_default_db_ready():
    global _default_db_initialized
    if not _default_db_initialized:
        try:
            with app.app_context():
                init_db()
            _default_db_initialized = True
        except Exception as e:
            print(f"[Init] default DB init error: {e}", flush=True)

def _render_landing():
    """Marketing page for the platform itself (shown at / when no store is selected)."""
    g.is_master = True  # skip per-store settings lookup in the context processor
    stores = []
    try:
        conn = get_master_db_connection()
        stores = conn.execute(
            "SELECT slug, store_name FROM tenants WHERE is_active = 1 ORDER BY id LIMIT 6"
        ).fetchall()
        conn.close()
    except Exception as e:
        print(f"[Landing] could not load stores: {e}", flush=True)
    demo_url = f"/s/{stores[0]['slug']}/" if stores else url_for('admin_login')
    # Optional sales WhatsApp number (digits with country code, e.g. 919876543210)
    wa_number = ''.join(ch for ch in os.environ.get('PLATFORM_WHATSAPP', '') if ch.isdigit())
    wa_url = ''
    if wa_number:
        wa_text = urllib.parse.quote("Hi! I'd like to get a VeloStore online store for my fashion business.")
        wa_url = f"https://wa.me/{wa_number}?text={wa_text}"
    return render_template('landing.html', stores=stores, plans=DEFAULT_PLAN_CONFIG,
                           demo_url=demo_url, wa_url=wa_url, now_year=datetime.utcnow().year)

# ---------------------------------------------------------------------------
# Friendly error pages (rendered without touching the database, so they work even if it is down)
# ---------------------------------------------------------------------------
def _error_page(code, title, message, error_id=None):
    home_url = '/'
    try:
        slug = getattr(g, 'tenant_slug', None)
        if slug and slug != 'master' and not getattr(g, 'is_master', False):
            home_url = url_for('index', shop=slug)
    except Exception:
        home_url = '/'
    html = app.jinja_env.get_template('error.html').render(
        code=code, title=title, message=message, home_url=home_url, error_id=error_id)
    return Response(html, status=code, mimetype='text/html')

@app.errorhandler(404)
def handle_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify(error='Not found'), 404
    return _error_page(404, 'Page not found',
                       "We couldn't find the page you were looking for. It may have moved or no longer exists.")

@app.errorhandler(500)
def handle_server_error(e):
    error_id = secrets.token_hex(4)
    original = getattr(e, 'original_exception', None) or e
    print(f"[Error {error_id}] {request.method} {request.path} -> {type(original).__name__}: {original}", flush=True)
    if request.path.startswith('/api/'):
        return jsonify(error='Something went wrong', reference=error_id), 500
    return _error_page(500, 'Something went wrong',
                       "Sorry, we hit a problem on our side. Please try again in a moment. "
                       "If it keeps happening, contact the store and share the reference below.",
                       error_id=error_id)

# ---------------------------------------------------------------------------
# Multi-Tenant Middleware & Database Connection
# ---------------------------------------------------------------------------
@app.url_defaults
def _add_shop_to_home_links(endpoint, values):
    """Links to the storefront home keep the current store, since '/' alone is the marketing page."""
    if endpoint == 'index' and 'shop' not in values:
        slug = getattr(g, 'tenant_slug', None)
        if slug and not getattr(g, 'is_master', False) and slug != 'master':
            values['shop'] = slug

@app.before_request
def resolve_tenant_context():
    """
    Middleware that identifies current tenant from:
    1. Header: X-Shop-Domain
    2. URL path: /s/<shop_slug>/
    3. Host custom domain or subdomain
    4. Query parameter: ?shop=<shop_slug>
    5. Session override
    Fallback: 'default'
    """
    path = request.path

    if path in ('/health', '/diag'):
        return

    _ensure_master_db_ready()
    _ensure_default_db_ready()

    # Check if request is for Master Admin
    if path.startswith('/master'):
        g.is_master = True
        g.tenant_slug = 'master'
        return

    g.is_master = False
    tenant_slug = None

    # Option 1: Header
    if 'X-Shop-Domain' in request.headers:
        tenant_slug = request.headers['X-Shop-Domain']

    # Option 2: Path prefix /s/<shop_slug>/
    elif path.startswith('/s/'):
        parts = path.split('/')
        if len(parts) >= 3 and parts[2]:
            tenant_slug = parts[2]

    # Option 3: Query Parameter ?shop=...
    elif request.args.get('shop'):
        raw_shop = request.args.get('shop').strip()
        tenant_slug = raw_shop.split('/')[0]

    # Option 4: Host custom domain
    else:
        host = request.host.split(':')[0]
        if host and host not in ('localhost', '127.0.0.1'):
            t_info = get_tenant_by_identifier(host)
            if t_info:
                tenant_slug = t_info['slug']

    # Marketing page at '/': shown whenever no store is explicitly named in the request
    # (no /s/slug, ?shop=, header or custom domain). The remembered session store is ignored
    # here. Storefront searches/filters on '/' still use the session store.
    _store_filter_args = {'q', 'category', 'min_price', 'max_price'}
    if (not tenant_slug and path == '/'
            and not (_store_filter_args & set(request.args.keys()))):
        return _render_landing()

    if not tenant_slug:
        tenant_slug = session.get('active_tenant_slug')

    tenant_info = get_tenant_by_identifier(tenant_slug) if tenant_slug else None
    if tenant_info:
        g.tenant = tenant_info
        g.tenant_slug = tenant_info['slug']
        g.tenant_features = get_tenant_feature_flags(tenant_info)
        session['active_tenant_slug'] = tenant_info['slug']
    else:
        default_tenant = get_tenant_by_identifier('default')
        g.tenant = default_tenant
        g.tenant_slug = 'default'
        g.tenant_features = get_tenant_feature_flags(default_tenant)

    # Check if tenant is suspended (inactive)
    if tenant_info and not tenant_info['is_active']:
        if not path.startswith('/static'):
            if session.get('master_logged_in') or session.get('is_impersonating'):
                pass  # Allow platform administrators to inspect or manage
            else:
                return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <title>{{ store_name }} | Store Temporarily Suspended</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link rel="preconnect" href="https://fonts.googleapis.com">
                    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@600;800&family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet">
                    <style>
                        body { margin: 0; background: #0a0f1d; color: #fff; font-family: 'Plus Jakarta Sans', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; box-sizing: border-box; }
                        .card { background: rgba(18, 24, 43, 0.95); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 20px; padding: 48px 32px; max-width: 480px; width: 100%; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
                        .icon { font-size: 3.5rem; margin-bottom: 16px; }
                        h1 { font-family: 'Outfit', sans-serif; font-size: 1.8rem; margin: 0 0 12px; color: #fff; }
                        p { color: #9ca3af; font-size: 0.95rem; line-height: 1.6; margin: 0 0 24px; }
                        .badge { display: inline-block; padding: 6px 14px; border-radius: 20px; background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 16px; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="icon">🛑</div>
                        <div class="badge">Store Offline</div>
                        <h1>{{ store_name }}</h1>
                        <p>This store is temporarily paused by platform administrators. Please check back later or contact customer support.</p>
                    </div>
                </body>
                </html>
                """, store_name=tenant_info['store_name']), 403

def check_expired_reservations(db):
    """Finds all orders with status 'Reserved' that have expired,
    restores their stock, and marks them as 'Expired'."""
    now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    cur = db.execute(
        "SELECT id FROM orders WHERE status = 'Reserved' AND reserved_until < ?",
        [now_utc]
    )
    expired_orders = cur.fetchall()

    if expired_orders:
        for order in expired_orders:
            order_id = order['id']
            # Fetch items in this order
            items_cur = db.execute(
                'SELECT product_id, quantity FROM order_items WHERE order_id = ?',
                [order_id]
            )
            items = items_cur.fetchall()
            for item in items:
                db.execute(
                    'UPDATE products SET stock = stock + ? WHERE id = ?',
                    [item['quantity'], item['product_id']]
                )
            # Update order status to Expired and clear reservation time
            db.execute(
                "UPDATE orders SET status = 'Expired', reserved_until = NULL WHERE id = ?",
                [order_id]
            )
        db.commit()

def get_db():
    if 'db' not in g:
        slug = getattr(g, 'tenant_slug', 'default')
        if slug == 'master':
            g.db = get_master_db_connection()
        else:
            g.db = get_tenant_db_connection(slug)

        # Run cleanup here without recursive get_db loop
        if not g.get('cleaning_reservations') and slug != 'master':
            g.cleaning_reservations = True
            try:
                check_expired_reservations(g.db)
            finally:
                g.cleaning_reservations = False
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database from schema.sql only if tables don't exist yet.
    Also inserts any new default settings that may be missing (migrations)."""
    db = get_connection()
    # Check if settings table already exists
    existing = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
    ).fetchone()
    if not existing:
        with open(os.path.join(BASE_DIR, 'schema.sql'), 'r', encoding='utf-8') as f:
            db.executescript(f.read())
        db.commit()

    # --- Migrations: add reserved_until column if missing ---
    try:
        db.execute("ALTER TABLE orders ADD COLUMN reserved_until TEXT")
        db.commit()
    except Exception:
        pass  # Already exists

    # --- Migrations: add post_office and district columns to customers if missing ---
    try:
        db.execute("ALTER TABLE customers ADD COLUMN post_office TEXT")
        db.commit()
    except Exception:
        pass

    try:
        db.execute("ALTER TABLE customers ADD COLUMN district TEXT")
        db.commit()
    except Exception:
        pass

    # --- Migrations: add landmark column to customers if missing ---
    try:
        db.execute("ALTER TABLE customers ADD COLUMN landmark TEXT")
        db.commit()
    except Exception:
        pass

    # --- Migrations: add image2 column to products if missing ---
    try:
        db.execute("ALTER TABLE products ADD COLUMN image2 TEXT")
        db.commit()
    except Exception:
        pass

    # --- Migrations: add size column to products if missing ---
    try:
        db.execute("ALTER TABLE products ADD COLUMN size TEXT")
        db.commit()
    except Exception:
        pass

    # --- Migrations: insert missing default settings for existing installs ---
    defaults = [
        ('show_out_of_stock', '1'),  # '1' = show them, '0' = hide them
        ('stock_reduction_mode', 'reserve'),  # 'reserve' = 15 min, 'manual' = manual updates
        ('reservation_minutes', '15'),  # hold stock for 15 minutes by default
        ('maintenance_mode', '0'),  # '0' = normal, '1' = storefront offline (maintenance mode)
        ('maintenance_message', 'We are currently updating our stock. Kindly visit later!'),
        ('shop_logo', ''),
    ]
    for key, value in defaults:
        db.execute(
            'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
            [key, value]
        )
    db.commit()
    db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur

# ---------------------------------------------------------------------------
# Settings Helper
# ---------------------------------------------------------------------------
def get_setting(key, default=''):
    row = query_db('SELECT value FROM settings WHERE key = ?', [key], one=True)
    return row['value'] if row else default

def set_setting(key, value):
    execute_db('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', [key, value])

def get_all_settings():
    rows = query_db('SELECT key, value FROM settings')
    return {row['key']: row['value'] for row in rows}

# ---------------------------------------------------------------------------
# Password Helpers
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Image Helpers (Cloudinary)
# ---------------------------------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file):
    """Upload image to Cloudinary. Local static/uploads/ fallback is development-only."""
    if not file or not allowed_file(file.filename):
        return None
    url = None
    try:
        url = cloudinary_helper.upload_image(file, folder="products")
    except Exception as e:
        print(f"[Cloudinary] upload exception: {e}")
    if url:
        return url
    if not LOCAL_UPLOADS_ALLOWED:
        flash('⚠️ Image upload failed, so the image was NOT saved. Please check the Cloudinary settings and try again.', 'error')
        return None
    # Development only: fall back to local storage
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{secrets.token_hex(8)}.{ext}"
        upload_dir = os.path.join(BASE_DIR, 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file.seek(0)
        file.save(os.path.join(upload_dir, filename))
        return filename
    except Exception as e:
        print(f"[Local Save] error: {e}")
        return None

def save_logo_image(file):
    """Upload shop logo to Cloudinary. Local fallback is development-only."""
    if not file or not allowed_file(file.filename):
        return None
    url = None
    try:
        url = cloudinary_helper.upload_logo(file, folder="branding")
    except Exception as e:
        print(f"[Cloudinary] logo upload exception: {e}")
    if url:
        return url
    if not LOCAL_UPLOADS_ALLOWED:
        flash('⚠️ Logo upload failed, so the logo was NOT saved. Please check the Cloudinary settings and try again.', 'error')
        return None
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"logo_{secrets.token_hex(6)}.{ext}"
        upload_dir = os.path.join(BASE_DIR, 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file.seek(0)
        file.save(os.path.join(upload_dir, filename))
        return filename
    except Exception as e:
        print(f"[Local Logo Save] error: {e}")
        return None

def delete_image(url):
    """Delete an image from Cloudinary."""
    if url:
        cloudinary_helper.delete_image(url)

# ---------------------------------------------------------------------------
# Auth Decorator & Rate Limiting Storage
# ---------------------------------------------------------------------------
FAILED_LOGIN_ATTEMPTS = {}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in') or session.get('admin_tenant_slug') != g.tenant_slug:
            shop_arg = g.tenant_slug if (getattr(g, 'tenant_slug', None) and g.tenant_slug != 'default') else None
            if shop_arg:
                return redirect(url_for('admin_login', shop=shop_arg))
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Template Helpers & Filters
# ---------------------------------------------------------------------------
@app.template_global()
def img_url(value):
    """Resolve an image value to a displayable URL.
    - If value is a full URL (Cloudinary), return as-is.
    - If value is a local filename (legacy), return /static/uploads/<filename>.
    - If value is empty/None, return empty string.
    """
    if not value:
        return ''
    if value.startswith(('http://', 'https://')):
        return value
    # Legacy local filename fallback
    return url_for('static', filename='uploads/' + value)

@app.template_filter('to_ist')
def to_ist_filter(utc_str):
    if not utc_str:
        return ""
    try:
        clean_str = utc_str.split('.')[0]
        dt = datetime.strptime(clean_str, '%Y-%m-%d %H:%M:%S')
        ist_dt = dt + timedelta(hours=5, minutes=30)
        return ist_dt.strftime('%Y-%m-%d %I:%M %p IST')
    except Exception:
        return utc_str

# ---------------------------------------------------------------------------
# Storage / Media Stats (adapted for Cloudinary)
# ---------------------------------------------------------------------------
def get_storage_stats():
    """Returns media metrics for the admin panel."""
    try:
        # Count images in DB (products + logo)
        products_with_img = query_db(
            "SELECT COUNT(*) as cnt FROM products WHERE image IS NOT NULL AND image != ''",
            one=True
        )
        products_with_img2 = query_db(
            "SELECT COUNT(*) as cnt FROM products WHERE image2 IS NOT NULL AND image2 != ''",
            one=True
        )
        img_count = (products_with_img['cnt'] if products_with_img else 0) + \
                    (products_with_img2['cnt'] if products_with_img2 else 0)

        logo = get_setting('shop_logo', '')
        if logo:
            img_count += 1

        return {
            'uploads_human': f'{img_count} images',
            'uploads_count': img_count,
            'storage_type': 'Cloudinary CDN' if cloudinary_helper._is_configured() else 'Local',
            'status': 'healthy'
        }
    except Exception:
        return {
            'uploads_human': '0 images',
            'uploads_count': 0,
            'storage_type': 'Unknown',
            'status': 'healthy'
        }

# ---------------------------------------------------------------------------
# Context Processor – injects shop settings and storage stats into templates
# ---------------------------------------------------------------------------
@app.context_processor
def inject_settings():
    if getattr(g, 'is_master', False) or request.path.startswith('/master'):
        return dict(settings={}, storage_stats={}, now_year=datetime.utcnow().year)

    settings = get_all_settings()
    tenant = getattr(g, 'tenant', None)
    features = getattr(g, 'tenant_features', {}) or (get_tenant_feature_flags(tenant) if tenant else {})
    tenant_theme = 'standard'
    if tenant:
        try:
            tenant_theme = tenant['theme'] if 'theme' in tenant.keys() else 'standard'
        except Exception:
            tenant_theme = 'standard'
    brand = (settings.get('shop_name') or '').strip()
    if not brand and tenant:
        try:
            brand = (tenant['store_name'] or '').strip()
        except Exception:
            brand = ''
    brand = brand or 'My Shop'
    ctx = dict(settings=settings, now_year=datetime.utcnow().year, tenant=tenant, tenant_features=features, tenant_theme=tenant_theme,
                 is_luxury=(tenant_theme in ('luxury', 'cocoa')), brand=brand)

    if request.path.startswith('/admin'):
        ctx['storage_stats'] = get_storage_stats()
        if tenant:
            try:
                p_cnt = query_db('SELECT COUNT(*) as cnt FROM products', one=True)['cnt']
                max_p = tenant.get('max_products', 100) if isinstance(tenant, dict) else tenant['max_products']
                ctx['tenant_product_count'] = p_cnt
                ctx['tenant_max_products'] = max_p
                ctx['tenant_product_usage_pct'] = min(100, int((p_cnt / max(1, max_p)) * 100))
            except Exception:
                pass
    return ctx
