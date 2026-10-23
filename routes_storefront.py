"""Customer-facing storefront routes (home, product pages, checkout, order success, /s/<store>)."""

import os
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from db import get_master_db_connection, get_tenant_by_identifier
from flask import abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from core import (_ensure_master_db_ready, _render_landing, app, get_db, get_setting, query_db,
                  rows_affected, app_config)

@app.route('/health')
def health_check():
    return jsonify(status="ok", timestamp=datetime.utcnow().isoformat()), 200

@app.route('/diag')
def diag():
    """Platform diagnostics. Only visible to a logged-in master admin; everyone else gets a plain 404."""
    if not session.get('master_logged_in'):
        abort(404)
    import threading, time, importlib.util
    url = os.environ.get('TURSO_DB_URL', '')
    info = {
        'flask_env': os.environ.get('FLASK_ENV'),
        'libsql_installed': importlib.util.find_spec('libsql') is not None,
        'TURSO_DB_URL_set': bool(url),
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

@app.route('/welcome')
def welcome():
    _ensure_master_db_ready()
    return _render_landing()

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
    cat_query = 'SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\''
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
        def fail(message, **extra):
            return jsonify({'success': False, 'error': message, **extra})

        # ---- 1. Read and validate the cart ----
        product_ids = request.form.getlist('product_id[]')
        quantities  = request.form.getlist('quantity[]')
        if not product_ids:
            return fail('Your cart is empty.')
        if len(product_ids) != len(quantities) or len(product_ids) > app_config.MAX_CART_LINES:
            return fail('Your cart could not be read. Please refresh the page and try again.')

        wanted = {}   # product id -> total quantity (repeated lines for one product are merged)
        try:
            for pid_raw, qty_raw in zip(product_ids, quantities):
                pid, qty = int(pid_raw), int(qty_raw)
                if qty < 1:
                    return fail('Quantity must be at least 1.')
                wanted[pid] = wanted.get(pid, 0) + qty
        except (TypeError, ValueError):
            return fail('Your cart contains invalid data. Please refresh the page and try again.')

        def current_stock_levels():
            levels = {}
            for check_pid in wanted:
                p_row = query_db('SELECT stock FROM products WHERE id = ?', [check_pid], one=True)
                levels[check_pid] = p_row['stock'] if p_row else 0
            return levels

        items = []
        total = 0.0
        for pid, qty in wanted.items():
            if qty > app_config.MAX_QTY_PER_ITEM:
                return fail(f'You can order at most {app_config.MAX_QTY_PER_ITEM} of one item at a time.')
            product = query_db('SELECT * FROM products WHERE id = ?', [pid], one=True)
            if not product:
                return fail('A product in your cart no longer exists.')
            if product['stock'] < qty:
                return fail(f'"{product["name"]}" only has {product["stock"]} item(s) left in stock.',
                            stock_updates=current_stock_levels())
            items.append({'product': product, 'quantity': qty})
            total += product['price'] * qty

        # ---- 2. Validate customer details ----
        name        = request.form.get('name', '').strip()
        phone       = request.form.get('phone', '').strip()
        whatsapp    = request.form.get('whatsapp', '').strip()
        # Support both legacy single address field and new Amazon-style split fields
        flat        = request.form.get('flat', '').strip()
        area        = request.form.get('area', '').strip()
        town_city   = request.form.get('town_city', '').strip()
        state       = request.form.get('state', '').strip()
        address_raw = request.form.get('address', '').strip()
        # Build combined address from split fields if provided, otherwise fall back to legacy
        if flat and area:
            address_parts = [flat, area]
            if town_city:
                address_parts.append(town_city)
            if state:
                address_parts.append(state)
            address = ', '.join(address_parts)
        else:
            address = address_raw
        landmark    = request.form.get('landmark', '').strip()
        post_office = request.form.get('post_office', '').strip()
        district    = request.form.get('district', '').strip()
        pincode     = request.form.get('pincode', '').strip()
        notes       = request.form.get('notes', '').strip()

        if not all([name, phone, whatsapp, address, post_office, district, pincode]):
            return fail('Please fill in all required fields.')
        phone_ok = lambda v: re.fullmatch(r'\+?[0-9][0-9 \-]{6,19}', v) is not None
        if not phone_ok(phone) or not phone_ok(whatsapp):
            return fail('Please enter a valid phone / WhatsApp number.')
        if not re.fullmatch(r'[0-9]{6}', pincode):
            return fail('Please enter a valid 6-digit pincode.')
        if (len(name) > 100 or len(address) > 500 or len(landmark) > 200 or len(post_office) > 100
                or len(district) > 100 or len(notes) > 300 or len(town_city) > 100 or len(state) > 100):
            return fail('One of the fields is too long. Please shorten it and try again.')

        # ---- 3. Save everything in ONE transaction ----
        db = get_db()
        stock_mode = get_setting('stock_reduction_mode', 'reserve')
        try:
            cur = db.execute(
                'INSERT INTO customers (name, phone, whatsapp, address, pincode, post_office, district, landmark) VALUES (?,?,?,?,?,?,?,?)',
                [name, phone, whatsapp, address, pincode, post_office, district, landmark]
            )
            customer_id = cur.lastrowid

            if stock_mode == 'manual':
                # Stock is updated manually by the shop owner; nothing is held here
                status, reserved_until = 'Pending', None
            else:
                try:
                    res_mins = min(max(int(get_setting('reservation_minutes', '15')), 1), 1440)
                except ValueError:
                    res_mins = 15
                status = 'Reserved'
                reserved_until = (datetime.utcnow() + timedelta(minutes=res_mins)).strftime('%Y-%m-%d %H:%M:%S')

            cur = db.execute(
                'INSERT INTO orders (customer_id, total, status, reserved_until) VALUES (?,?,?,?)',
                [customer_id, total, status, reserved_until]
            )
            order_id = cur.lastrowid

            for item in items:
                pid, qty = item['product']['id'], item['quantity']
                db.execute(
                    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)',
                    [order_id, pid, qty, item['product']['price']]
                )
                if stock_mode != 'manual':
                    # Atomic "take stock only if enough is left". If two customers buy the last item
                    # at the same moment, exactly one of these UPDATEs changes a row.
                    took = db.execute(
                        'UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?', [qty, pid, qty])
                    changed = rows_affected(took)
                    if changed is None:   # driver can't report rows changed: verify by reading back
                        check = db.execute('SELECT stock FROM products WHERE id = ?', [pid]).fetchone()
                        changed = 1 if check and check['stock'] >= 0 else 0
                    if changed == 0:
                        db.rollback()
                        return fail(f'Sorry, "{item["product"]["name"]}" just sold out or has less stock than you '
                                    f'asked for. Please review your bag.', stock_updates=current_stock_levels())
            db.commit()
        except Exception:
            db.rollback()
            raise

        # Keep the session small: the WhatsApp message is rebuilt from the database on the next page
        session['last_order'] = {
            'shop': g.tenant_slug,   # an order confirmation only ever shows inside the shop it was placed in
            'order_id': order_id,
            'notes': notes,
        }
        return jsonify({'success': True, 'redirect_url': url_for('order_success')})

    # GET – render the checkout page with cart data from query params
    return render_template('checkout.html')

def _build_order_confirmation(order_id, notes=''):
    """Rebuild the confirmation page data and the WhatsApp message from the database."""
    row = query_db(
        '''SELECT o.id, o.total, c.name, c.phone, c.address, c.landmark, c.post_office, c.district, c.pincode
           FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = ?''', [order_id], one=True)
    if not row:
        return None
    items = query_db(
        '''SELECT oi.quantity, oi.price, p.name FROM order_items oi
           LEFT JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?''', [order_id])
    shop_name = get_setting('shop_name', 'Our Shop')
    wa_number = ''.join(ch for ch in get_setting('whatsapp_number', '') if ch.isdigit())
    currency = get_setting('currency_symbol', '₹')
    total = row['total']

    lines = [
        f"🛍️ *New Order from {shop_name}!*\n",
        f"📋 *Order ID:* #{order_id}",
        f"👤 *Customer:* {row['name']}",
        f"📞 *Phone:* {row['phone']}",
        f"📍 *Address:* {row['address']}",
    ]
    if row['landmark']:
        lines.append(f"🏠 *Landmark:* {row['landmark']}")
    if row['post_office']:
        lines.append(f"📦 *Post Office (P.O.):* {row['post_office']}")
    if row['district']:
        lines.append(f"🏙️ *District:* {row['district']}")
    lines.append(f"📮 *Pincode:* {row['pincode']}")
    if notes:
        lines.append(f"📝 *Notes:* {notes}")
    lines.append("\n🛒 *Items Ordered:*")
    for it in items:
        lines.append(f"  • {it['quantity']} x {it['name'] or 'Item'} — {currency}{it['price']:.2f}")
    lines.append(f"\n💰 *Total Amount:* {currency}{total:.2f} + Delivery Charges")
    return {
        'customer_name': row['name'], 'order_id': order_id, 'currency': currency, 'total': total,
        'wa_number': wa_number, 'wa_message': '\n'.join(lines),
    }

@app.route('/order-success')
def order_success():
    last = session.get('last_order', None)
    if not last or last.get('shop') != g.tenant_slug or not last.get('order_id'):
        return redirect(url_for('index'))
    order_data = _build_order_confirmation(last['order_id'], last.get('notes', ''))
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

_ADMIN_PATH_RE = re.compile(r'admin(?:/[A-Za-z0-9_\-]+)+')

def _safe_admin_path(clean_sub):
    """Return '/admin/...' only if it is a plain path (no '..', '//', '?', '#') that matches a real
    admin route; otherwise None. Prevents crafted /s/<shop>/admin/... links from redirecting oddly."""
    if not _ADMIN_PATH_RE.fullmatch(clean_sub):
        return None
    path = '/' + clean_sub
    try:
        app.url_map.bind('localhost').match(path, method='GET')
    except HTTPException:
        return None
    return path

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

    slug = tenant['slug']   # the middleware already remembers the active store; no extra session write here
    clean_sub = subpath.strip('/')

    if clean_sub == 'admin' or clean_sub == 'admin/dashboard':
        return redirect(url_for('admin_dashboard', shop=slug))
    elif clean_sub == 'admin/login':
        return redirect(url_for('admin_login', shop=slug))
    elif clean_sub.startswith('admin/'):
        safe_path = _safe_admin_path(clean_sub)
        if safe_path:
            return redirect(f'{safe_path}?shop={quote(slug, safe="")}')
        return redirect(url_for('admin_dashboard', shop=slug))

    return redirect(url_for('index', shop=slug))
