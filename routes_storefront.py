"""Customer-facing storefront routes (home, product pages, checkout, order success, /s/<store>)."""

import os
from datetime import datetime, timedelta
from db import get_master_db_connection, get_tenant_by_identifier
from flask import flash, jsonify, redirect, render_template, request, session, url_for
from core import _ensure_master_db_ready, _render_landing, app, get_db, get_setting, query_db

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
