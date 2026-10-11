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
from config import get_config
from db import (Database, get_connection, is_turso, init_master_db,
                get_master_db_connection, get_tenant_by_identifier,
                get_tenant_db_connection, provision_new_tenant,
                get_tenant_feature_flags, update_tenant_admin_password,
                delete_tenant, DEFAULT_PLAN_CONFIG)
import cloudinary_helper

# ---------------------------------------------------------------------------
# App Configuration & Multi-Tenant Setup
# ---------------------------------------------------------------------------
app_config = get_config()
app = Flask(__name__)
app.secret_key = app_config.SECRET_KEY

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ALLOWED_EXTENSIONS = app_config.ALLOWED_EXTENSIONS

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

@app.route('/health')
def health_check():
    return jsonify(status="ok", timestamp=datetime.utcnow().isoformat()), 200

@app.route('/diag')
def diag():
    """Safe diagnostics: shows env presence + tests Turso with a 10s timeout. No secrets shown."""
    import threading, time, importlib.util
    url = os.environ.get('TURSO_DB_URL', '')
    info = {
        'flask_env': os.environ.get('FLASK_ENV'),
        'libsql_installed': importlib.util.find_spec('libsql') is not None,
        'TURSO_DB_URL_set': bool(url),
        'TURSO_DB_URL_prefix': url[:9] + '...' if url else '',
        'TURSO_DB_URL_has_whitespace': url != url.strip(),
        'TURSO_AUTH_TOKEN_set': bool(os.environ.get('TURSO_AUTH_TOKEN')),
        'CLOUDINARY_set': bool(os.environ.get('CLOUDINARY_CLOUD_NAME') and os.environ.get('CLOUDINARY_API_KEY') and os.environ.get('CLOUDINARY_API_SECRET')),
    }
    result = {}
    def _test():
        t = time.time()
        try:
            conn = get_master_db_connection()
            result['connected_in_s'] = round(time.time() - t, 2)
            rows = conn.execute("SELECT 1").fetchall()
            result['select_1'] = str(rows)
            result['total_s'] = round(time.time() - t, 2)
            conn.close()
        except Exception as e:
            result['error'] = f"{type(e).__name__}: {e}"
    th = threading.Thread(target=_test, daemon=True)
    th.start()
    th.join(10)
    if th.is_alive():
        result['error'] = 'TIMEOUT: Turso connection did not respond within 10s'
    return jsonify(env=info, turso_test=result), 200

# ---------------------------------------------------------------------------
# Multi-Tenant Middleware & Database Connection
# ---------------------------------------------------------------------------
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
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------------------------------------------------------------------
# Image Helpers (Cloudinary)
# ---------------------------------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file):
    """Upload image to Cloudinary (if configured), fallback to local static/uploads/."""
    if not file or not allowed_file(file.filename):
        return None
    url = None
    try:
        url = cloudinary_helper.upload_image(file, folder="products")
    except Exception as e:
        print(f"[Cloudinary] upload exception: {e}")
    if url:
        return url
    # Fallback to local storage if Cloudinary returns None or is unconfigured
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
    """Upload shop logo to Cloudinary, fallback to local static/uploads/."""
    if not file or not allowed_file(file.filename):
        return None
    url = None
    try:
        url = cloudinary_helper.upload_logo(file, folder="branding")
    except Exception as e:
        print(f"[Cloudinary] logo upload exception: {e}")
    if url:
        return url
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
    ctx = dict(settings=settings, now_year=datetime.utcnow().year, tenant=tenant, tenant_features=features, tenant_theme=tenant_theme)

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


# ===========================================================================
# CUSTOMER ROUTES
# ===========================================================================

@app.route('/')
def index():
    search = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()

    # Price filter params
    min_price_raw = request.args.get('min_price', '').strip()
    max_price_raw = request.args.get('max_price', '').strip()
    try:
        min_price = float(min_price_raw) if min_price_raw else None
    except ValueError:
        min_price = None
    try:
        max_price = float(max_price_raw) if max_price_raw else None
    except ValueError:
        max_price = None

    # Respect the admin toggle: hide out-of-stock products if disabled
    show_oos = get_setting('show_out_of_stock', '1')

    query = 'SELECT * FROM products WHERE 1=1'
    args = []
    if show_oos == '0':
        # Hide products with zero stock entirely from the customer page
        query += ' AND stock > 0'
    if search:
        query += ' AND (name LIKE ? OR description LIKE ?)'
        args += [f'%{search}%', f'%{search}%']
    if category:
        query += ' AND category = ?'
        args.append(category)
    if min_price is not None:
        query += ' AND price >= ?'
        args.append(min_price)
    if max_price is not None:
        query += ' AND price <= ?'
        args.append(max_price)
    # Order in-stock products first, then by newest addition
    query += ' ORDER BY CASE WHEN stock > 0 THEN 0 ELSE 1 END ASC, created_at DESC'

    products = query_db(query, args)

    # Distinct categories for the filter bar (only from visible products)
    cat_query = 'SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ""'
    if show_oos == '0':
        cat_query += ' AND stock > 0'
    cat_query += ' ORDER BY category'
    categories = [row['category'] for row in query_db(cat_query)]

    # Price range of ALL visible products (for placeholder hints)
    price_range = query_db(
        'SELECT MIN(price) as min_p, MAX(price) as max_p FROM products WHERE 1=1' +
        (' AND stock > 0' if show_oos == '0' else ''),
        one=True
    )

    return render_template('index.html',
                           products=products,
                           categories=categories,
                           search=search,
                           active_category=category,
                           min_price=min_price_raw,
                           max_price=max_price_raw,
                           price_range=price_range)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = query_db('SELECT * FROM products WHERE id = ?', [product_id], one=True)
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
    # Related products (same category, different id)
    related = query_db(
        'SELECT * FROM products WHERE category = ? AND id != ? AND stock > 0 LIMIT 4',
        [product['category'], product_id]
    )
    return render_template('product_detail.html', product=product, related=related)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if get_setting('maintenance_mode', '0') == '1':
        if request.method == 'POST':
            return jsonify({'success': False, 'error': get_setting('maintenance_message', 'Store is currently undergoing maintenance. Please try again later.')})
        else:
            flash(get_setting('maintenance_message', 'Store is currently undergoing maintenance. Please try again later.'), 'info')
            return redirect(url_for('index'))

    if request.method == 'POST':
        # Collect cart items from hidden fields
        product_ids = request.form.getlist('product_id[]')
        quantities  = request.form.getlist('quantity[]')

        if not product_ids:
            return jsonify({'success': False, 'error': 'Your cart is empty.'})

        # Validate stock for each item
        items = []
        total = 0.0
        for pid, qty in zip(product_ids, quantities):
            pid = int(pid)
            qty = int(qty)
            product = query_db('SELECT * FROM products WHERE id = ?', [pid], one=True)
            if not product:
                return jsonify({'success': False, 'error': 'A product in your cart no longer exists.'})
            if product['stock'] < qty:
                # Compile current database stock levels for items in checkout request
                stock_updates = {}
                for check_pid in product_ids:
                    p_row = query_db('SELECT stock FROM products WHERE id = ?', [int(check_pid)], one=True)
                    stock_updates[int(check_pid)] = p_row['stock'] if p_row else 0
                return jsonify({
                    'success': False,
                    'error': f'"{product["name"]}" only has {product["stock"]} item(s) left in stock.',
                    'stock_updates': stock_updates
                })
            items.append({'product': product, 'quantity': qty})
            total += product['price'] * qty

        # Customer details
        name        = request.form.get('name', '').strip()
        phone       = request.form.get('phone', '').strip()
        whatsapp    = request.form.get('whatsapp', '').strip()
        address     = request.form.get('address', '').strip()
        landmark    = request.form.get('landmark', '').strip()
        post_office = request.form.get('post_office', '').strip()
        district    = request.form.get('district', '').strip()
        pincode     = request.form.get('pincode', '').strip()
        notes       = request.form.get('notes', '').strip()

        if not all([name, phone, whatsapp, address, post_office, district, pincode]):
            return jsonify({'success': False, 'error': 'Please fill in all required fields.'})

        # Save customer
        db = get_db()
        cur = db.execute(
            'INSERT INTO customers (name, phone, whatsapp, address, pincode, post_office, district, landmark) VALUES (?,?,?,?,?,?,?,?)',
            [name, phone, whatsapp, address, pincode, post_office, district, landmark]
        )
        customer_id = cur.lastrowid

        # Get stock reduction mode setting
        stock_mode = get_setting('stock_reduction_mode', 'reserve')

        if stock_mode == 'manual':
            # Save order with Pending status and no expiration
            cur = db.execute(
                'INSERT INTO orders (customer_id, total, status, reserved_until) VALUES (?,?,?,?)',
                [customer_id, total, 'Pending', None]
            )
            order_id = cur.lastrowid

            # Save order items without reducing stock
            for item in items:
                pid = item['product']['id']
                qty = item['quantity']
                db.execute(
                    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)',
                    [order_id, pid, qty, item['product']['price']]
                )
        else:
            # Save order with Reserved status and dynamic expiration duration
            res_mins = int(get_setting('reservation_minutes', '15'))
            reserved_until = (datetime.utcnow() + timedelta(minutes=res_mins)).strftime('%Y-%m-%d %H:%M:%S')
            cur = db.execute(
                'INSERT INTO orders (customer_id, total, status, reserved_until) VALUES (?,?,?,?)',
                [customer_id, total, 'Reserved', reserved_until]
            )
            order_id = cur.lastrowid

            # Save order items and reduce stock
            for item in items:
                pid = item['product']['id']
                qty = item['quantity']
                db.execute(
                    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)',
                    [order_id, pid, qty, item['product']['price']]
                )
                db.execute('UPDATE products SET stock = stock - ? WHERE id = ?', [qty, pid])

        db.commit()

        # Build WhatsApp message
        shop_name = get_setting('shop_name', 'Our Shop')
        wa_number = get_setting('whatsapp_number', '')
        currency  = get_setting('currency_symbol', '₹')

        lines = [
            f"🛍️ *New Order from {shop_name}!*\n",
            f"📋 *Order ID:* #{order_id}",
            f"👤 *Customer:* {name}",
            f"📞 *Phone:* {phone}",
            f"📍 *Address:* {address}",
        ]
        if landmark:
            lines.append(f"🏠 *Landmark:* {landmark}")
        if post_office:
            lines.append(f"📦 *Post Office (P.O.):* {post_office}")
        if district:
            lines.append(f"🏙️ *District:* {district}")
        lines.append(f"📮 *Pincode:* {pincode}")
        if notes:
            lines.append(f"📝 *Notes:* {notes}")
        lines.append("\n🛒 *Items Ordered:*")
        for item in items:
            p = item['product']
            lines.append(f"  • {item['quantity']} x {p['name']} — {currency}{p['price']:.2f}")
        lines.append(f"\n💰 *Total Amount:* {currency}{total:.2f} + Delivery Charges")
        wa_message = '\n'.join(lines)

        # Store order info in session for the order success page
        session['last_order'] = {
            'customer_name': name,
            'order_id': order_id,
            'currency': currency,
            'total': total,
            'wa_number': wa_number,
            'wa_message': wa_message
        }

        # Return JSON containing redirect URL to local success page
        return jsonify({'success': True, 'redirect_url': url_for('order_success')})

    # GET – render the checkout page with cart data from query params
    return render_template('checkout.html')


@app.route('/order-success')
def order_success():
    order_data = session.get('last_order', None)
    if not order_data:
        return redirect(url_for('index'))
    return render_template('order_success.html', order=order_data)


# API: get product info (for cart validation)
@app.route('/api/product/<int:product_id>')
def api_product(product_id):
    product = query_db('SELECT id, name, price, stock, image, image2 FROM products WHERE id = ?', [product_id], one=True)
    if not product:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(product))


# Serve admin service worker at root of admin scope
@app.route('/admin-sw.js')
def admin_sw():
    from flask import send_from_directory
    return send_from_directory('static', 'admin-sw.js',
                               mimetype='application/javascript')


# ===========================================================================
# ADMIN ROUTES
# ===========================================================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in') and session.get('admin_tenant_slug') == g.tenant_slug:
        return redirect(url_for('admin_dashboard', shop=g.tenant_slug))
    if request.method == 'POST':
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
        attempt_key = f"{g.tenant_slug}:{client_ip}"
        now = datetime.now()

        # Check for active lockout
        if attempt_key in FAILED_LOGIN_ATTEMPTS:
            attempts, lockout_until = FAILED_LOGIN_ATTEMPTS[attempt_key]
            if attempts >= 5 and now < lockout_until:
                remaining_sec = int((lockout_until - now).total_seconds())
                flash(f"🔒 Security Lockout: Too many failed login attempts. Please wait {remaining_sec} seconds before trying again.", 'error')
                return render_template('admin/login.html')
            elif now >= lockout_until:
                FAILED_LOGIN_ATTEMPTS.pop(attempt_key, None)

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        shop_slug = request.form.get('shop_slug', '').strip().lower() or request.args.get('shop', '').strip().lower()

        target_slug = shop_slug or (g.tenant_slug if getattr(g, 'tenant_slug', 'default') != 'default' else None)

        authenticated_slug = None
        pwd_hash = hash_password(password)

        def verify_credentials_for_slug(slug_to_check):
            """Helper to verify username & password against a specific tenant database & master record."""
            try:
                # 1. Check master info for email / slug matching
                m_conn = get_master_db_connection()
                cur = m_conn.cursor()
                cur.execute("SELECT slug, owner_email, is_active FROM tenants WHERE slug = ?", [slug_to_check])
                tenant_rec = cur.fetchone()
                m_conn.close()

                if tenant_rec and not tenant_rec['is_active']:
                    return False

                owner_email = (tenant_rec['owner_email'] or '').strip().lower() if tenant_rec else ''

                # 2. Check tenant db settings
                t_conn = get_tenant_db_connection(slug_to_check)
                u_row = t_conn.execute("SELECT value FROM settings WHERE key = 'admin_username'").fetchone()
                p_row = t_conn.execute("SELECT value FROM settings WHERE key = 'admin_password'").fetchone()
                t_conn.close()

                stored_user = (u_row['value'] if u_row else 'admin').strip()
                stored_pass = (p_row['value'] if p_row else 'admin123').strip()

                user_matches = (
                    username.lower() == stored_user.lower() or
                    (owner_email and username.lower() == owner_email) or
                    username.lower() == slug_to_check.lower()
                )

                pass_matches = (
                    password == stored_pass or
                    pwd_hash == stored_pass or
                    pwd_hash.lower() == stored_pass.lower()
                )

                return user_matches and pass_matches
            except Exception:
                return False

        # Step 1: If target_slug is specified, check that tenant first
        if target_slug:
            if verify_credentials_for_slug(target_slug):
                authenticated_slug = target_slug

        # Step 2: Search across all active tenants in master.db
        if not authenticated_slug:
            try:
                m_conn = get_master_db_connection()
                cur = m_conn.cursor()
                cur.execute("SELECT slug FROM tenants WHERE is_active = 1")
                all_tenants = cur.fetchall()
                m_conn.close()
                for row in all_tenants:
                    candidate_slug = row['slug']
                    if target_slug and candidate_slug == target_slug:
                        continue
                    if verify_credentials_for_slug(candidate_slug):
                        authenticated_slug = candidate_slug
                        break
            except Exception:
                pass

        # Step 3: Check default database
        if not authenticated_slug and target_slug != 'default':
            if verify_credentials_for_slug('default'):
                authenticated_slug = 'default'

        if authenticated_slug:
            FAILED_LOGIN_ATTEMPTS.pop(attempt_key, None)
            session['active_tenant_slug'] = authenticated_slug
            session['admin_tenant_slug'] = authenticated_slug
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session.permanent = True
            flash('Welcome back! 👋', 'success')
            return redirect(url_for('admin_dashboard', shop=authenticated_slug))

        # Record failed attempt
        if attempt_key not in FAILED_LOGIN_ATTEMPTS:
            FAILED_LOGIN_ATTEMPTS[attempt_key] = (1, now + timedelta(seconds=300))
        else:
            attempts, _ = FAILED_LOGIN_ATTEMPTS[attempt_key]
            FAILED_LOGIN_ATTEMPTS[attempt_key] = (attempts + 1, now + timedelta(seconds=300))

        remaining = 5 - FAILED_LOGIN_ATTEMPTS[attempt_key][0]
        if remaining > 0:
            flash(f'Invalid username, store identifier, or password. ({remaining} attempt{"s" if remaining > 1 else ""} remaining before lockout)', 'error')
        else:
            flash('🔒 Too many failed attempts. Account temporarily locked out for 5 minutes for security.', 'error')

    return render_template('admin/login.html')


@app.route('/admin/logout')
def admin_logout():
    if session.get('is_impersonating'):
        return redirect(url_for('master_stop_impersonating'))
    current_shop = session.get('admin_tenant_slug') or session.get('active_tenant_slug')
    session.clear()
    flash('You have been logged out.', 'info')
    if current_shop and current_shop != 'default':
        return redirect(url_for('admin_login', shop=current_shop))
    return redirect(url_for('admin_login'))


@app.route('/admin')
@login_required
def admin_dashboard():
    total_products = query_db('SELECT COUNT(*) as cnt FROM products', one=True)['cnt']
    total_orders   = query_db('SELECT COUNT(*) as cnt FROM orders', one=True)['cnt']
    total_revenue  = query_db("SELECT COALESCE(SUM(total),0) as rev FROM orders WHERE status NOT IN ('Cancelled', 'Expired')", one=True)['rev']
    pending_orders = query_db("SELECT COUNT(*) as cnt FROM orders WHERE status = 'Reserved'", one=True)['cnt']
    low_stock      = query_db('SELECT * FROM products WHERE stock <= 2 AND stock > 0 ORDER BY stock ASC')
    out_of_stock   = query_db('SELECT COUNT(*) as cnt FROM products WHERE stock = 0', one=True)['cnt']
    recent_orders  = query_db(
        '''SELECT o.id, o.total, o.status, o.created_at, c.name as customer_name
           FROM orders o JOIN customers c ON o.customer_id = c.id
           ORDER BY o.created_at DESC LIMIT 5'''
    )
    # Monthly revenue – last 6 months (simplified)
    monthly = query_db(
        """SELECT strftime('%Y-%m', created_at) as month, SUM(total) as revenue
           FROM orders WHERE status NOT IN ('Cancelled', 'Expired')
           GROUP BY month ORDER BY month DESC LIMIT 6"""
    )
    return render_template('admin/dashboard.html',
                           total_products=total_products,
                           total_orders=total_orders,
                           total_revenue=total_revenue,
                           pending_orders=pending_orders,
                           low_stock=low_stock,
                           out_of_stock=out_of_stock,
                           recent_orders=recent_orders,
                           monthly=monthly)


# ---- Products ----

@app.route('/admin/products')
@login_required
def admin_products():
    search   = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    q = 'SELECT * FROM products WHERE 1=1'
    args = []
    if search:
        q += ' AND (name LIKE ? OR description LIKE ?)'
        args += [f'%{search}%', f'%{search}%']
    if category:
        q += ' AND category = ?'
        args.append(category)
    q += ' ORDER BY created_at DESC'
    products = query_db(q, args)
    categories = [row['category'] for row in
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category')]
    return render_template('admin/products.html',
                           products=products,
                           categories=categories,
                           search=search,
                           active_category=category)


@app.route('/admin/purchases')
@login_required
def admin_purchases():
    search   = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    q = 'SELECT * FROM products WHERE 1=1'
    args = []
    if search:
        q += ' AND (name LIKE ? OR description LIKE ?)'
        args += [f'%{search}%', f'%{search}%']
    if category:
        q += ' AND category = ?'
        args.append(category)
    q += ' ORDER BY name ASC'
    products = query_db(q, args)
    categories = [row['category'] for row in
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category')]
    return render_template('admin/purchases.html',
                           products=products,
                           categories=categories,
                           search=search,
                           active_category=category)


@app.route('/api/admin/products/<int:product_id>/sales')
@login_required
def api_product_sales(product_id):
    sales = query_db(
        '''SELECT o.id as order_id, o.created_at, o.status, c.name as customer_name, c.phone, oi.quantity
           FROM order_items oi
           JOIN orders o ON oi.order_id = o.id
           JOIN customers c ON o.customer_id = c.id
           WHERE oi.product_id = ?
           ORDER BY o.created_at DESC''', [product_id]
    )
    sales_list = []
    for sale in sales:
        sales_list.append({
            'order_id': sale['order_id'],
            'customer_name': sale['customer_name'],
            'phone': sale['phone'],
            'quantity': sale['quantity'],
            'status': sale['status'],
            'created_at': to_ist_filter(sale['created_at'])
        })
    return jsonify(sales_list)


@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    categories = [row['category'] for row in
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category')]
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price       = request.form.get('price', '0')
        stock       = request.form.get('stock', '0')
        category    = request.form.get('category', '').strip()
        new_cat     = request.form.get('new_category', '').strip()
        size        = request.form.get('size', '').strip()
        if new_cat:
            category = new_cat

        # Primary Image (Cover) → Cloudinary
        image_file = request.files.get('image')
        image_url = save_image(image_file) if image_file and image_file.filename else None

        # Secondary Image (Angle / Detail) → Cloudinary
        image2_file = request.files.get('image2')
        image2_url = save_image(image2_file) if image2_file and image2_file.filename else None

        if not name or not price:
            flash('Name and price are required.', 'error')
            return render_template('admin/product_form.html', product=None, categories=categories, action='Add')

        # Enforce max_products plan limit
        max_allowed = 100
        if getattr(g, 'tenant', None) and g.tenant:
            try:
                max_allowed = g.tenant['max_products'] if 'max_products' in g.tenant.keys() else 100
            except Exception:
                max_allowed = 100
        current_count = query_db('SELECT COUNT(*) as cnt FROM products', one=True)['cnt']
        if current_count >= max_allowed:
            flash(f'Product limit reached for your plan (Maximum: {max_allowed} products). Please contact platform admin to upgrade.', 'error')
            return render_template('admin/product_form.html', product=None, categories=categories, action='Add')

        execute_db(
            'INSERT INTO products (name, description, price, stock, image, image2, category, size) VALUES (?,?,?,?,?,?,?,?)',
            [name, description, float(price), int(stock), image_url, image2_url, category, size]
        )
        flash(f'Product "{name}" added successfully! 🎉', 'success')
        return redirect(url_for('admin_products'))

    return render_template('admin/product_form.html', product=None, categories=categories, action='Add')


@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    product = query_db('SELECT * FROM products WHERE id = ?', [product_id], one=True)
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('admin_products'))
    categories = [row['category'] for row in
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != "" ORDER BY category')]
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price       = request.form.get('price', '0')
        stock       = request.form.get('stock', '0')
        category    = request.form.get('category', '').strip()
        new_cat     = request.form.get('new_category', '').strip()
        size        = request.form.get('size', '').strip()
        if new_cat:
            category = new_cat

        # Primary Image (Cover)
        image_file = request.files.get('image')
        image_url = product['image']  # keep existing
        remove_image1 = request.form.get('remove_image1') == '1'
        if remove_image1:
            delete_image(image_url)
            image_url = None
        elif image_file and image_file.filename:
            new_img = save_image(image_file)
            if new_img:
                delete_image(image_url)  # Remove old from Cloudinary
                image_url = new_img

        # Secondary Image (Angle / Detail)
        image2_file = request.files.get('image2')
        image2_url = product['image2'] if 'image2' in product.keys() else None
        remove_image2 = request.form.get('remove_image2') == '1'
        if remove_image2:
            delete_image(image2_url)
            image2_url = None
        elif image2_file and image2_file.filename:
            new_img2 = save_image(image2_file)
            if new_img2:
                delete_image(image2_url)  # Remove old from Cloudinary
                image2_url = new_img2

        execute_db(
            'UPDATE products SET name=?, description=?, price=?, stock=?, image=?, image2=?, category=?, size=? WHERE id=?',
            [name, description, float(price), int(stock), image_url, image2_url, category, size, product_id]
        )
        flash(f'Product "{name}" updated successfully! ✅', 'success')
        return redirect(url_for('admin_products'))

    return render_template('admin/product_form.html', product=product, categories=categories, action='Edit')


@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    product = query_db('SELECT * FROM products WHERE id = ?', [product_id], one=True)
    if product:
        delete_image(product['image'])
        if 'image2' in product.keys() and product['image2']:
            delete_image(product['image2'])
        execute_db('DELETE FROM products WHERE id = ?', [product_id])
        flash(f'Product "{product["name"]}" deleted.', 'success')
    return redirect(url_for('admin_products'))


# ---- Orders ----

@app.route('/admin/orders')
@login_required
def admin_orders():
    status_filter = request.args.get('status', '').strip()
    search_query = request.args.get('q', '').strip()
    date_filter = request.args.get('date_filter', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    q = '''SELECT o.id, o.total, o.status, o.created_at,
                  c.name as customer_name, c.phone
           FROM orders o JOIN customers c ON o.customer_id = c.id
           WHERE 1=1'''
    args = []

    # 1. Search Query (Order ID, Customer Name, Phone)
    if search_query:
        clean_search = search_query.lstrip('#')
        search_pattern = f'%{clean_search}%'
        if clean_search.isdigit():
            q += ' AND (o.id = ? OR LOWER(c.name) LIKE LOWER(?) OR LOWER(c.phone) LIKE LOWER(?))'
            args.extend([int(clean_search), search_pattern, search_pattern])
        else:
            q += ' AND (LOWER(c.name) LIKE LOWER(?) OR LOWER(c.phone) LIKE LOWER(?))'
            args.extend([search_pattern, search_pattern])

    # 2. Status Filter
    if status_filter:
        q += ' AND o.status = ?'
        args.append(status_filter)

    # 3. Date Range Filter (based on IST date)
    now_utc = datetime.utcnow()
    now_ist = now_utc + timedelta(hours=5, minutes=30)
    today_ist = now_ist.strftime('%Y-%m-%d')
    yesterday_ist = (now_ist - timedelta(days=1)).strftime('%Y-%m-%d')
    seven_days_ago_ist = (now_ist - timedelta(days=6)).strftime('%Y-%m-%d')

    if date_filter == 'today':
        q += " AND date(o.created_at, '+5 hours', '30 minutes') = ?"
        args.append(today_ist)
    elif date_filter == 'yesterday':
        q += " AND date(o.created_at, '+5 hours', '30 minutes') = ?"
        args.append(yesterday_ist)
    elif date_filter == 'week':
        q += " AND date(o.created_at, '+5 hours', '30 minutes') BETWEEN ? AND ?"
        args.extend([seven_days_ago_ist, today_ist])
    elif date_filter == 'custom':
        if start_date:
            q += " AND date(o.created_at, '+5 hours', '30 minutes') >= ?"
            args.append(start_date)
        if end_date:
            q += " AND date(o.created_at, '+5 hours', '30 minutes') <= ?"
            args.append(end_date)

    q += ' ORDER BY o.created_at DESC'
    orders = query_db(q, args)

    return render_template('admin/orders.html',
                           orders=orders,
                           status_filter=status_filter,
                           search_query=search_query,
                           date_filter=date_filter,
                           start_date=start_date,
                           end_date=end_date)



@app.route('/admin/orders/<int:order_id>')
@login_required
def admin_order_detail(order_id):
    order = query_db(
        '''SELECT o.*, c.name as customer_name, c.phone, c.whatsapp, c.address, c.pincode, c.post_office, c.district, c.landmark
           FROM orders o JOIN customers c ON o.customer_id = c.id
           WHERE o.id = ?''', [order_id], one=True
    )
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('admin_orders'))
    items = query_db(
        '''SELECT oi.id, oi.product_id, oi.quantity, oi.price, p.name as product_name, p.image, p.size
           FROM order_items oi LEFT JOIN products p ON oi.product_id = p.id
           WHERE oi.order_id = ?''', [order_id]
    )
    return render_template('admin/order_detail.html', order=order, items=items)


@app.route('/admin/orders/<int:order_id>/item/<int:item_id>/cancel', methods=['POST'])
@login_required
def admin_cancel_order_item(order_id, item_id):
    db = get_db()
    order = query_db('SELECT * FROM orders WHERE id = ?', [order_id], one=True)
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('admin_orders'))

    if order['status'] in ('Cancelled', 'Expired'):
        flash(f'Cannot modify items for an order that is already {order["status"]}.', 'error')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    item = query_db(
        '''SELECT oi.*, p.name as product_name 
           FROM order_items oi 
           LEFT JOIN products p ON oi.product_id = p.id 
           WHERE oi.id = ? AND oi.order_id = ?''',
        [item_id, order_id],
        one=True
    )
    if not item:
        flash('Order item not found.', 'error')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    action_type = request.form.get('action', 'cancel_one')
    if action_type == 'cancel_all' or item['quantity'] <= 1:
        cancel_qty = item['quantity']
    else:
        try:
            req_qty = int(request.form.get('quantity', 1))
            cancel_qty = min(max(1, req_qty), item['quantity'])
        except (ValueError, TypeError):
            cancel_qty = 1

    active_statuses = {'Pending', 'Confirmed', 'Shipped', 'Reserved'}
    stock_mode = get_setting('stock_reduction_mode', 'reserve')

    # Return stock if order was active and stock reduction mode is 'reserve'
    if stock_mode == 'reserve' and order['status'] in active_statuses and item['product_id']:
        db.execute('UPDATE products SET stock = stock + ? WHERE id = ?', [cancel_qty, item['product_id']])

    # Update or remove order item
    if cancel_qty >= item['quantity']:
        db.execute('DELETE FROM order_items WHERE id = ?', [item_id])
    else:
        db.execute('UPDATE order_items SET quantity = quantity - ? WHERE id = ?', [cancel_qty, item_id])

    # Recalculate order total
    remaining = query_db(
        'SELECT COALESCE(SUM(quantity * price), 0) as new_total, COUNT(*) as remaining_items FROM order_items WHERE order_id = ?',
        [order_id],
        one=True
    )
    new_total = remaining['new_total'] if remaining else 0
    remaining_items = remaining['remaining_items'] if remaining else 0

    pname = item['product_name'] or 'Product'
    curr = get_setting('currency_symbol', '₹')

    if remaining_items == 0:
        db.execute('UPDATE orders SET total = 0, status = "Cancelled", reserved_until = NULL WHERE id = ?', [order_id])
        db.commit()
        flash(f'Cancelled "{pname}". All items cancelled, so Order #{order_id} is now Cancelled. Stock restored (+{cancel_qty}). 🔄', 'warning')
    else:
        db.execute('UPDATE orders SET total = ? WHERE id = ?', [new_total, order_id])
        db.commit()
        flash(f'Cancelled {cancel_qty}x "{pname}". Stock restored (+{cancel_qty}) and order total updated to {curr}{new_total:.2f}. 🔄', 'success')

    return redirect(url_for('admin_order_detail', order_id=order_id))


@app.route('/admin/orders/<int:order_id>/status', methods=['POST'])
@login_required
def admin_update_order_status(order_id):
    new_status = request.form.get('status', 'Pending')

    db = get_db()
    # Get current status
    order = query_db('SELECT status FROM orders WHERE id = ?', [order_id], one=True)
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('admin_orders'))

    old_status = order['status']

    # Active statuses that reserve stock
    active_statuses = {'Pending', 'Confirmed', 'Shipped', 'Reserved'}
    inactive_statuses = {'Cancelled', 'Expired'}

    # Get stock reduction mode setting
    stock_mode = get_setting('stock_reduction_mode', 'reserve')

    if stock_mode == 'reserve':
        # Transition: Active -> Inactive (release stock)
        if old_status in active_statuses and new_status in inactive_statuses:
            items = query_db('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [order_id])
            for item in items:
                db.execute('UPDATE products SET stock = stock + ? WHERE id = ?', [item['quantity'], item['product_id']])
            db.commit()
            flash(f'Order #{order_id} marked as {new_status}. Stock restored to inventory. 🔄', 'info')

        # Transition: Inactive -> Active (re-reserve stock)
        elif old_status in inactive_statuses and new_status in active_statuses:
            items = query_db('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [order_id])
            for item in items:
                db.execute('UPDATE products SET stock = stock - ? WHERE id = ?', [item['quantity'], item['product_id']])
            db.commit()
            flash(f'Order #{order_id} re-activated. Stock reserved from inventory. 📦', 'info')

    # If the order is confirmed, shipped, or cancelled, clear the reservation timer
    if new_status != 'Reserved':
        execute_db('UPDATE orders SET reserved_until = NULL WHERE id = ?', [order_id])

    # Update status
    execute_db('UPDATE orders SET status = ? WHERE id = ?', [new_status, order_id])
    flash(f'Order #{order_id} status updated to {new_status}.', 'success')
    return redirect(url_for('admin_order_detail', order_id=order_id))


# ---- Settings ----

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if request.method == 'POST':
        shop_name    = request.form.get('shop_name', '').strip()
        shop_slogan  = request.form.get('shop_slogan', '').strip()
        shop_tagline = request.form.get('shop_tagline', '').strip()
        whatsapp     = request.form.get('whatsapp_number', '').strip()
        currency_s   = request.form.get('currency_symbol', '₹').strip()
        currency_c   = request.form.get('currency_code', 'INR').strip()
        new_user     = request.form.get('admin_username', '').strip()
        new_pass     = request.form.get('admin_password', '').strip()
        confirm      = request.form.get('confirm_password', '').strip()
        # Checkbox: present = '1' (show), absent = '0' (hide)
        show_oos     = '1' if request.form.get('show_out_of_stock') else '0'
        stock_mode   = request.form.get('stock_reduction_mode', 'reserve')
        res_mins     = request.form.get('reservation_minutes', '15').strip()
        store_notice = request.form.get('store_notice', '').strip()

        if shop_name:
            set_setting('shop_name', shop_name)
        set_setting('shop_slogan', shop_slogan)
        set_setting('shop_tagline', shop_tagline)
        if whatsapp:
            set_setting('whatsapp_number', whatsapp)
        set_setting('currency_symbol', currency_s)
        set_setting('currency_code', currency_c)
        set_setting('show_out_of_stock', show_oos)
        set_setting('stock_reduction_mode', stock_mode)
        set_setting('reservation_minutes', res_mins)
        set_setting('store_notice', store_notice)

        # Shop Logo Upload & Removal (Cloudinary)
        remove_logo = request.form.get('remove_logo') == '1'
        logo_file = request.files.get('shop_logo')

        if remove_logo:
            old_logo = get_setting('shop_logo', '')
            if old_logo:
                delete_image(old_logo)
            set_setting('shop_logo', '')
        elif logo_file and logo_file.filename:
            new_logo = save_logo_image(logo_file)
            if new_logo:
                old_logo = get_setting('shop_logo', '')
                if old_logo and old_logo != new_logo:
                    delete_image(old_logo)
                set_setting('shop_logo', new_logo)

        maintenance_mode = '1' if request.form.get('maintenance_mode') else '0'
        maintenance_msg  = request.form.get('maintenance_message', '').strip()
        set_setting('maintenance_mode', maintenance_mode)
        set_setting('maintenance_message', maintenance_msg or 'We are currently updating our stock. Kindly visit later!')
        if new_user:
            set_setting('admin_username', new_user)
            session['admin_username'] = new_user
        if new_pass:
            if len(new_pass) < 6:
                flash('🔒 Password Security Error: New password must be at least 6 characters long.', 'error')
                return redirect(url_for('admin_settings'))
            if new_pass != confirm:
                flash('🔒 Password Security Error: Passwords do not match.', 'error')
                return redirect(url_for('admin_settings'))
            set_setting('admin_password', hash_password(new_pass))
            flash('🔐 Admin password updated securely. Please log in with your new credentials.', 'info')
            session.clear()
            return redirect(url_for('admin_login'))

        flash('Settings saved successfully! ✅', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('admin/settings.html')


@app.route('/admin/clear-data', methods=['POST'])
@login_required
def admin_clear_data():
    clear_type = request.form.get('clear_type', '')
    db = get_db()

    if clear_type == 'orders':
        db.execute('DELETE FROM order_items')
        db.execute('DELETE FROM orders')
        db.commit()
        flash('All orders and order items have been deleted. 🗑️', 'success')

    elif clear_type == 'customers':
        # Cascades to orders and order_items via FK ON DELETE CASCADE
        db.execute('DELETE FROM order_items')
        db.execute('DELETE FROM orders')
        db.execute('DELETE FROM customers')
        db.commit()
        flash('All customers, orders, and order items have been deleted. 🗑️', 'success')

    elif clear_type == 'all':
        db.execute('DELETE FROM order_items')
        db.execute('DELETE FROM orders')
        db.execute('DELETE FROM customers')
        db.commit()
        flash('All data cleared — orders, order items, and customers deleted. 🗑️', 'success')

    else:
        flash('Unknown clear type.', 'error')

    return redirect(url_for('admin_settings'))


# ===========================================================================
# Master Admin & Multi-Tenant Routes
# ===========================================================================

def master_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('master_logged_in'):
            flash('Master Administrator authentication required.', 'error')
            return redirect(url_for('master_login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/master/login', methods=['GET', 'POST'])
def master_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        pwd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        m_conn = get_master_db_connection()
        cur = m_conn.cursor()
        cur.execute(
            "SELECT * FROM master_admins WHERE username = ? AND password_hash = ?",
            [username, pwd_hash]
        )
        admin = cur.fetchone()
        m_conn.close()

        if admin:
            session['master_logged_in'] = True
            session['master_username'] = admin['username']
            flash('Welcome to Master Control Panel! ⚡', 'success')
            return redirect(url_for('master_dashboard'))

        flash('Invalid master username or password.', 'error')

    return render_template('master/login.html')


@app.route('/master/logout')
def master_logout():
    session.pop('master_logged_in', None)
    session.pop('master_username', None)
    flash('Logged out of Master Control Panel.', 'info')
    return redirect(url_for('master_login'))


@app.route('/master/dashboard')
@master_login_required
def master_dashboard():
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()

    cur.execute("SELECT * FROM tenants ORDER BY created_at DESC")
    raw_tenants = cur.fetchall()

    cur.execute("SELECT COUNT(*) as cnt FROM tenants")
    total_shops = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM tenants WHERE is_active = 1")
    active_shops = cur.fetchone()['cnt']

    cur.execute("SELECT COUNT(*) as cnt FROM tenants WHERE is_active = 0")
    suspended_shops = cur.fetchone()['cnt']

    total_products_global = 0
    total_orders_global = 0
    total_revenue_global = 0.0
    total_customers_global = 0
    plan_counts = {'free': 0, 'basic': 0, 'premium': 0}

    tenants = []
    for row in raw_tenants:
        t = dict(row)
        plan = t.get('plan', 'free') or 'free'
        plan_counts[plan] = plan_counts.get(plan, 0) + 1

        p_cnt = 0
        o_cnt = 0
        rev = 0.0
        c_cnt = 0

        adm_usr = 'admin'
        try:
            t_conn = get_tenant_db_connection(t['slug'])
            u_row = t_conn.execute("SELECT value FROM settings WHERE key = 'admin_username'").fetchone()
            if u_row and u_row['value']:
                adm_usr = u_row['value']
            p_cnt = t_conn.execute("SELECT COUNT(*) as cnt FROM products").fetchone()['cnt']
            o_cnt = t_conn.execute("SELECT COUNT(*) as cnt FROM orders").fetchone()['cnt']
            rev_row = t_conn.execute("SELECT COALESCE(SUM(total), 0) as rev FROM orders WHERE status NOT IN ('Cancelled', 'Expired')").fetchone()
            rev = float(rev_row['rev']) if rev_row else 0.0
            c_cnt = t_conn.execute("SELECT COUNT(*) as cnt FROM customers").fetchone()['cnt']
            t_conn.close()
        except Exception:
            pass

        t['admin_username'] = adm_usr

        t['product_count'] = p_cnt
        t['order_count'] = o_cnt
        t['revenue'] = rev
        t['customer_count'] = c_cnt
        t['features'] = get_tenant_feature_flags(t)
        max_p = t.get('max_products', 100) or 100
        t['usage_pct'] = min(100, int((p_cnt / max(1, max_p)) * 100))

        total_products_global += p_cnt
        total_orders_global += o_cnt
        total_revenue_global += rev
        total_customers_global += c_cnt

        tenants.append(t)

    m_conn.close()

    stats = {
        'total_shops': total_shops,
        'active_shops': active_shops,
        'suspended_shops': suspended_shops,
        'total_products_global': total_products_global,
        'total_orders_global': total_orders_global,
        'total_revenue_global': total_revenue_global,
        'total_customers_global': total_customers_global,
        'plan_counts': plan_counts,
    }

    return render_template('master/dashboard.html', tenants=tenants, stats=stats)


@app.route('/master/tenants/new', methods=['GET', 'POST'])
@master_login_required
def master_tenant_new():
    if request.method == 'POST':
        store_name = request.form.get('store_name', '').strip()
        slug = request.form.get('slug', '').strip().lower()
        owner_name = request.form.get('owner_name', '').strip()
        owner_email = request.form.get('owner_email', '').strip()
        owner_phone = request.form.get('owner_phone', '').strip()
        custom_domain = request.form.get('custom_domain', '').strip()
        plan = request.form.get('plan', 'free')
        theme = request.form.get('theme', 'standard')
        try:
            max_products = int(request.form.get('max_products', 100))
        except ValueError:
            max_products = 100
        admin_username = request.form.get('admin_username', '').strip() or 'admin'
        admin_password = request.form.get('admin_password', 'admin123')

        # Feature flags toggles
        feature_flags = {
            'custom_domain': bool(request.form.get('flag_custom_domain')),
            'analytics': bool(request.form.get('flag_analytics')),
            'export_csv': bool(request.form.get('flag_export_csv')),
            'discount_codes': bool(request.form.get('flag_discount_codes')),
            'whatsapp_checkout': bool(request.form.get('flag_whatsapp_checkout')),
            'pos_receipt': bool(request.form.get('flag_pos_receipt')),
        }

        try:
            provision_new_tenant(
                slug=slug,
                store_name=store_name,
                owner_name=owner_name,
                owner_email=owner_email,
                owner_phone=owner_phone,
                plan=plan,
                theme=theme,
                max_products=max_products,
                custom_domain=custom_domain,
                admin_username=admin_username,
                admin_password=admin_password,
                feature_flags=feature_flags
            )
            flash(f"Store database for '{store_name}' (/s/{slug}) successfully provisioned! 🚀 (Login: {admin_username})", 'success')
            return redirect(url_for('master_dashboard'))
        except Exception as e:
            flash(f"Error provisioning store: {str(e)}", 'error')

    return render_template('master/tenant_form.html', tenant=None, default_plans=DEFAULT_PLAN_CONFIG, action='Create')


@app.route('/master/tenants/<int:tenant_id>/edit', methods=['GET', 'POST'])
@master_login_required
def master_tenant_edit(tenant_id):
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()
    cur.execute("SELECT * FROM tenants WHERE id = ?", [tenant_id])
    tenant_row = cur.fetchone()

    if not tenant_row:
        m_conn.close()
        flash("Store tenant not found.", "error")
        return redirect(url_for('master_dashboard'))

    tenant = dict(tenant_row)

    if request.method == 'POST':
        store_name = request.form.get('store_name', '').strip()
        owner_name = request.form.get('owner_name', '').strip()
        owner_email = request.form.get('owner_email', '').strip()
        owner_phone = request.form.get('owner_phone', '').strip()
        custom_domain = request.form.get('custom_domain', '').strip()
        plan = request.form.get('plan', 'free')
        theme = request.form.get('theme', 'standard')
        try:
            max_products = int(request.form.get('max_products', 100))
        except ValueError:
            max_products = 100
        is_active = 1 if request.form.get('is_active') else 0

        # Feature flags toggles
        feature_flags = {
            'custom_domain': bool(request.form.get('flag_custom_domain')),
            'analytics': bool(request.form.get('flag_analytics')),
            'export_csv': bool(request.form.get('flag_export_csv')),
            'discount_codes': bool(request.form.get('flag_discount_codes')),
            'whatsapp_checkout': bool(request.form.get('flag_whatsapp_checkout')),
            'pos_receipt': bool(request.form.get('flag_pos_receipt')),
        }
        flags_json = json.dumps(feature_flags)

        cur.execute("""
        UPDATE tenants SET store_name=?, owner_name=?, owner_email=?, owner_phone=?, custom_domain=?, plan=?, theme=?, max_products=?, is_active=?, feature_flags=?
        WHERE id=?
        """, [store_name, owner_name, owner_email, owner_phone, custom_domain or None, plan, theme or 'standard', max_products, is_active, flags_json, tenant_id])
        m_conn.commit()
        m_conn.close()

        # Update tenant settings shop_name, phone, and optional admin_username
        new_username = request.form.get('admin_username', '').strip()
        try:
            t_conn = get_tenant_db_connection(tenant['slug'])
            t_conn.execute("UPDATE settings SET value = ? WHERE key = 'shop_name'", [store_name])
            if owner_phone:
                t_conn.execute("UPDATE settings SET value = ? WHERE key = 'whatsapp_number'", [owner_phone])
            if new_username:
                t_conn.execute("UPDATE settings SET value = ? WHERE key = 'admin_username'", [new_username])
            t_conn.commit()
            t_conn.close()
        except Exception:
            pass

        # Optional Admin Password Reset
        new_password = request.form.get('admin_password', '').strip()
        if new_password:
            try:
                update_tenant_admin_password(tenant['slug'], new_password)
                flash(f"Admin password for '{store_name}' was also updated! 🔑", "info")
            except Exception as e:
                flash(f"Failed to reset admin password: {str(e)}", "error")

        flash(f"Store settings for '{store_name}' updated successfully! ✅", "success")
        return redirect(url_for('master_dashboard'))

    m_conn.close()
    current_admin_username = 'admin'
    try:
        t_conn = get_tenant_db_connection(tenant['slug'])
        row = t_conn.execute("SELECT value FROM settings WHERE key = 'admin_username'").fetchone()
        if row and row['value']:
            current_admin_username = row['value']
        t_conn.close()
    except Exception:
        pass

    tenant_features = get_tenant_feature_flags(tenant)
    return render_template('master/tenant_form.html', tenant=tenant, tenant_features=tenant_features, current_admin_username=current_admin_username, default_plans=DEFAULT_PLAN_CONFIG, action='Edit')


@app.route('/master/tenants/<int:tenant_id>/toggle-status', methods=['POST'])
@master_login_required
def master_toggle_tenant(tenant_id):
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()

    cur.execute("SELECT is_active, store_name FROM tenants WHERE id = ?", [tenant_id])
    tenant = cur.fetchone()

    if tenant:
        new_status = 0 if tenant['is_active'] else 1
        cur.execute("UPDATE tenants SET is_active = ? WHERE id = ?", [new_status, tenant_id])
        m_conn.commit()
        status_label = "activated" if new_status else "suspended"
        flash(f"Store '{tenant['store_name']}' has been {status_label}.", 'info')

    m_conn.close()
    return redirect(url_for('master_dashboard'))


@app.route('/master/tenants/<int:tenant_id>/delete', methods=['POST'])
@master_login_required
def master_tenant_delete(tenant_id):
    try:
        store_name = delete_tenant(tenant_id)
        flash(f"Store '{store_name}' has been permanently deleted. 🗑️", 'info')
    except Exception as e:
        flash(f"Could not delete store: {str(e)}", 'error')
    return redirect(url_for('master_dashboard'))


@app.route('/master/tenants/<int:tenant_id>/login-as')
@master_login_required
def master_impersonate(tenant_id):
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()
    cur.execute("SELECT id, slug, store_name FROM tenants WHERE id = ?", [tenant_id])
    tenant = cur.fetchone()
    m_conn.close()

    if tenant:
        session['active_tenant_slug'] = tenant['slug']
        session['admin_tenant_slug'] = tenant['slug']
        session['admin_logged_in'] = True
        session['admin_username'] = f"MasterAdmin ({session.get('master_username', 'master')})"
        session['is_impersonating'] = True
        session['impersonated_tenant_id'] = tenant['id']
        session['impersonated_tenant_slug'] = tenant['slug']
        session['impersonated_tenant_name'] = tenant['store_name']
        flash(f"🔑 Impersonating '{tenant['store_name']}'. You now have full store admin control.", 'info')
        return redirect(url_for('admin_dashboard', shop=tenant['slug']))

    flash("Tenant not found.", "error")
    return redirect(url_for('master_dashboard'))


@app.route('/master/stop-impersonation')
def master_stop_impersonating():
    tenant_name = session.pop('impersonated_tenant_name', 'Store')
    session.pop('is_impersonating', None)
    session.pop('impersonated_tenant_id', None)
    session.pop('impersonated_tenant_slug', None)
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session['active_tenant_slug'] = 'default'
    flash(f"Exited impersonation mode for '{tenant_name}'. Returned to Master Panel.", "info")
    return redirect(url_for('master_dashboard'))


@app.route('/admin/export/<export_type>')
@login_required
def admin_export_csv(export_type):
    features = getattr(g, 'tenant_features', {}) or {}
    if not features.get('export_csv'):
        flash('CSV Export is a Basic & Premium plan feature. Please contact the platform admin to upgrade.', 'error')
        return redirect(url_for('admin_purchases'))

    output = io.StringIO()
    writer = csv.writer(output)

    if export_type == 'products':
        products = query_db('SELECT id, name, category, price, stock, size, created_at FROM products ORDER BY id ASC')
        writer.writerow(['Product ID', 'Name', 'Category', 'Price', 'Stock', 'Size', 'Created At'])
        for p in products:
            writer.writerow([p['id'], p['name'], p['category'], p['price'], p['stock'], p['size'], p['created_at']])
        filename = f"{g.tenant_slug}_products_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    elif export_type == 'orders':
        orders = query_db('''
            SELECT o.id, c.name as customer_name, c.phone, c.address, o.total, o.status, o.created_at
            FROM orders o
            LEFT JOIN customers c ON o.customer_id = c.id
            ORDER BY o.id DESC
        ''')
        writer.writerow(['Order ID', 'Customer Name', 'Phone', 'Address', 'Total Amount', 'Status', 'Date'])
        for o in orders:
            writer.writerow([o['id'], o['customer_name'], o['phone'], o['address'], o['total'], o['status'], o['created_at']])
        filename = f"{g.tenant_slug}_orders_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    else:
        flash('Invalid export type requested.', 'error')
        return redirect(url_for('admin_dashboard'))

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


@app.route('/s/<shop_slug>/', defaults={'subpath': ''})
@app.route('/s/<shop_slug>/<path:subpath>')
def storefront_shop(shop_slug, subpath):
    """
    Subpath storefront & admin entry point (/s/shop_slug/ or /s/shop_slug/admin)
    """
    tenant = get_tenant_by_identifier(shop_slug)
    if not tenant:
        flash("Store not found.", "error")
        return redirect(url_for('index'))

    session['active_tenant_slug'] = shop_slug
    clean_sub = subpath.strip('/')

    if clean_sub == 'admin' or clean_sub == 'admin/dashboard':
        return redirect(url_for('admin_dashboard', shop=shop_slug))
    elif clean_sub == 'admin/login':
        return redirect(url_for('admin_login', shop=shop_slug))
    elif clean_sub.startswith('admin/'):
        target = clean_sub.replace('admin/', '', 1)
        return redirect(f'/admin/{target}?shop={shop_slug}')

    return redirect(url_for('index', shop=shop_slug))


# ===========================================================================
# Entry Point
# ===========================================================================

# DB setup now runs lazily on first real request (see _ensure_default_db_ready),
# so a slow/unreachable Turso can never block the worker from starting.

if __name__ == '__main__':
    app.run(debug=True, port=5000)