"""Store-owner admin routes (login, products, orders, settings, exports)."""

import csv
import io
import re
from datetime import datetime, timedelta
from db import get_master_db_connection, get_tenant_db_connection
from flask import Response, flash, g, jsonify, redirect, render_template, request, session, url_for
from security import hash_password, needs_rehash, verify_password, validate_new_password
import ratelimit
from core import (
    app,
    client_ip,
    rows_affected,
    delete_image,
    execute_db,
    get_db,
    get_setting,
    login_required,
    query_db,
    save_image,
    save_logo_image,
    set_setting,
    to_ist_filter,
)

def _parse_product_fields(form):
    """Validate product form input. Returns (cleaned_dict, error_message)."""
    name = form.get('name', '').strip()
    if not name:
        return None, 'Name and price are required.'
    if len(name) > 200:
        return None, 'Product name is too long (max 200 characters).'
    try:
        price = float(form.get('price', '').strip())
    except ValueError:
        return None, 'Price must be a number.'
    if price != price or price in (float('inf'), float('-inf')) or price < 0 or price > 10_000_000:
        return None, 'Price must be between 0 and 10,000,000.'
    try:
        stock = int(form.get('stock', '0').strip() or '0')
    except ValueError:
        return None, 'Stock must be a whole number.'
    if stock < 0 or stock > 1_000_000:
        return None, 'Stock must be between 0 and 1,000,000.'
    description = form.get('description', '').strip()
    if len(description) > 5000:
        return None, 'Description is too long (max 5000 characters).'
    category = form.get('new_category', '').strip() or form.get('category', '').strip()
    size = form.get('size', '').strip()
    if len(category) > 100 or len(size) > 200:
        return None, 'Category or size text is too long.'
    return dict(name=name, description=description, price=price, stock=stock, category=category, size=size), None

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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        shop_slug = request.form.get('shop_slug', '').strip().lower() or request.args.get('shop', '').strip().lower()
        target_slug = shop_slug or (g.tenant_slug if getattr(g, 'tenant_slug', 'default') != 'default' else None)

        # Brute-force protection stored in the database (survives restarts, shared by all workers).
        # One counter per visitor IP (across all stores) plus a looser one per targeted store, so a
        # spread-out attack on a single store is slowed down as well.
        ip_key = f"admin-ip:{client_ip()}"
        store_key = f"admin-store:{target_slug or 'default'}"
        locked = ratelimit.seconds_locked(ip_key, store_key)
        if locked:
            flash(f"🔒 Security Lockout: Too many failed login attempts. Please wait {locked} seconds before trying again.", 'error')
            return render_template('admin/login.html'), 429

        authenticated_slug = None

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
                if not p_row or not (p_row['value'] or '').strip():
                    return False   # no password set: nobody can log in (never fall back to a default)
                stored_pass = p_row['value'].strip()

                user_matches = (
                    username.lower() == stored_user.lower() or
                    (owner_email and username.lower() == owner_email) or
                    username.lower() == slug_to_check.lower()
                )

                # Only run the (deliberately slow) password check when the username fits
                if not user_matches:
                    return False
                if not verify_password(password, stored_pass):
                    return False

                # Upgrade legacy SHA-256 / plain-text passwords to a salted hash after a good login
                if p_row and needs_rehash(stored_pass):
                    print(f"[Security] store '{slug_to_check}' logged in with a legacy-format password; upgrading it to a salted hash.", flush=True)
                    try:
                        up_conn = get_tenant_db_connection(slug_to_check)
                        up_conn.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)",
                            [hash_password(password)]
                        )
                        up_conn.commit()
                        up_conn.close()
                    except Exception as e:
                        print(f"[Security] could not upgrade password hash for '{slug_to_check}': {e}", flush=True)
                return True
            except Exception:
                return False

        # Authenticate ONLY against the specific shop the user is trying to log into.
        # Never fall back to scanning other shops — that would let overlapping
        # credentials grant access to a different store.
        if target_slug:
            if verify_credentials_for_slug(target_slug):
                authenticated_slug = target_slug
        else:
            # No shop context at all — try the default database only
            if verify_credentials_for_slug('default'):
                authenticated_slug = 'default'

        if authenticated_slug:
            ratelimit.clear(ip_key)
            session.clear()   # fresh session on login (prevents session fixation)
            session['active_tenant_slug'] = authenticated_slug
            session['admin_tenant_slug'] = authenticated_slug
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session.permanent = True
            flash('Welcome back! 👋', 'success')
            return redirect(url_for('admin_dashboard', shop=authenticated_slug))

        # Record failed attempt
        remaining = ratelimit.record_failure(ip_key)
        ratelimit.record_failure(store_key, max_attempts=30, lockout=300)
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
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category')]
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
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category')]
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
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category')]
    if request.method == 'POST':
        fields, error = _parse_product_fields(request.form)
        if error:
            flash(error, 'error')
            return render_template('admin/product_form.html', product=None, categories=categories, action='Add')
        name, description, price, stock = fields['name'], fields['description'], fields['price'], fields['stock']
        category, size = fields['category'], fields['size']

        # Check the plan limit BEFORE uploading images (so a rejected product never leaves orphan images)
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

        # Primary Image (Cover) → Cloudinary
        image_file = request.files.get('image')
        image_url = save_image(image_file) if image_file and image_file.filename else None

        # Secondary Image (Angle / Detail) → Cloudinary
        image2_file = request.files.get('image2')
        image2_url = save_image(image2_file) if image2_file and image2_file.filename else None

        execute_db(
            'INSERT INTO products (name, description, price, stock, image, image2, category, size) VALUES (?,?,?,?,?,?,?,?)',
            [name, description, price, stock, image_url, image2_url, category, size]
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
                  query_db('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category')]
    if request.method == 'POST':
        fields, error = _parse_product_fields(request.form)
        if error:
            flash(error, 'error')
            return render_template('admin/product_form.html', product=product, categories=categories, action='Edit')
        name, description, price, stock = fields['name'], fields['description'], fields['price'], fields['stock']
        category, size = fields['category'], fields['size']

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
            [name, description, price, stock, image_url, image2_url, category, size, product_id]
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
        db.execute('UPDATE orders SET total = 0, status = \'Cancelled\', reserved_until = NULL WHERE id = ?', [order_id])
        db.commit()
        flash(f'Cancelled "{pname}". All items cancelled, so Order #{order_id} is now Cancelled. Stock restored (+{cancel_qty}). 🔄', 'warning')
    else:
        db.execute('UPDATE orders SET total = ? WHERE id = ?', [new_total, order_id])
        db.commit()
        flash(f'Cancelled {cancel_qty}x "{pname}". Stock restored (+{cancel_qty}) and order total updated to {curr}{new_total:.2f}. 🔄', 'success')

    return redirect(url_for('admin_order_detail', order_id=order_id))

ORDER_STATUSES = ('Reserved', 'Pending', 'Confirmed', 'Shipped', 'Cancelled', 'Expired')

@app.route('/admin/orders/<int:order_id>/status', methods=['POST'])
@login_required
def admin_update_order_status(order_id):
    new_status = request.form.get('status', '').strip()
    if new_status not in ORDER_STATUSES:
        flash('Invalid order status.', 'error')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    db = get_db()
    order = query_db('SELECT status FROM orders WHERE id = ?', [order_id], one=True)
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('admin_orders'))

    old_status = order['status']
    if old_status == new_status:
        flash(f'Order #{order_id} is already {new_status}.', 'info')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    # Active statuses that hold stock
    active_statuses = {'Pending', 'Confirmed', 'Shipped', 'Reserved'}
    inactive_statuses = {'Cancelled', 'Expired'}
    stock_mode = get_setting('stock_reduction_mode', 'reserve')

    # Claim the transition atomically: only if the order is still in the status we just read.
    # (Two admins clicking at once, or the expiry cleanup, can no longer restore the same stock twice.)
    keep_timer = 'reserved_until' if new_status == 'Reserved' else 'NULL'
    claim = db.execute(
        f'UPDATE orders SET status = ?, reserved_until = {keep_timer} WHERE id = ? AND status = ?',
        [new_status, order_id, old_status])
    if rows_affected(claim) == 0:
        db.rollback()
        flash('This order was just changed by someone else. Please review it and try again.', 'warning')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    note = None
    if stock_mode == 'reserve':
        items = query_db('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [order_id])
        # Active -> Inactive: release stock
        if old_status in active_statuses and new_status in inactive_statuses:
            for item in items:
                db.execute('UPDATE products SET stock = stock + ? WHERE id = ?', [item['quantity'], item['product_id']])
            note = f'Order #{order_id} marked as {new_status}. Stock restored to inventory. 🔄'
        # Inactive -> Active: take stock again, but only if enough is left
        elif old_status in inactive_statuses and new_status in active_statuses:
            for item in items:
                if not item['product_id']:
                    continue
                took = db.execute(
                    'UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?',
                    [item['quantity'], item['product_id'], item['quantity']])
                if rows_affected(took) == 0:
                    db.rollback()
                    flash(f'Order #{order_id} could not be re-activated: not enough stock for one of its items.', 'error')
                    return redirect(url_for('admin_order_detail', order_id=order_id))
            note = f'Order #{order_id} re-activated. Stock reserved from inventory. 📦'

    db.commit()
    if note:
        flash(note, 'info')
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
        current_pw   = request.form.get('current_password', '').strip()

        # Validate a password change first, so a failed change never leaves settings half-saved
        if new_pass:
            if not session.get('is_impersonating'):
                if not verify_password(current_pw, get_setting('admin_password', '')):
                    flash('🔒 Password NOT changed: your current password is incorrect.', 'error')
                    return redirect(url_for('admin_settings'))
            pw_error = validate_new_password(new_pass, new_user or session.get('admin_username', ''))
            if pw_error:
                flash(f'🔒 Password Security Error: {pw_error}', 'error')
                return redirect(url_for('admin_settings'))
            if new_pass != confirm:
                flash('🔒 Password Security Error: Passwords do not match.', 'error')
                return redirect(url_for('admin_settings'))

        if shop_name:
            set_setting('shop_name', shop_name)
        set_setting('shop_slogan', shop_slogan)
        set_setting('shop_tagline', shop_tagline)
        if whatsapp:
            set_setting('whatsapp_number', whatsapp)
        set_setting('currency_symbol', currency_s)
        set_setting('currency_code', currency_c)
        set_setting('show_out_of_stock', show_oos)
        try:
            res_mins = str(min(max(int(res_mins), 1), 1440))
        except ValueError:
            res_mins = '15'
        if stock_mode not in ('reserve', 'manual'):
            stock_mode = 'reserve'
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
            from db import change_admin_username
            try:
                # claims the name in the master table (unique index), then saves it in this store's settings
                change_admin_username(g.tenant_slug, new_user, lambda name: set_setting('admin_username', name))
            except ValueError:
                flash(f'⚠️ Username "{new_user}" is already used by another store. Please choose a different username.', 'error')
                return redirect(url_for('admin_settings'))
            session['admin_username'] = new_user
        if new_pass:
            set_setting('admin_password', hash_password(new_pass))
            shop_slug_now = g.tenant_slug
            session.clear()   # sign out everywhere after a password change...
            flash('🔐 Admin password updated securely. Please log in with your new credentials.', 'info')   # ...then flash (clear() used to wipe this message)
            return redirect(url_for('admin_login', shop=shop_slug_now))

        flash('Settings saved successfully! ✅', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('admin/settings.html')

@app.route('/admin/clear-data', methods=['POST'])
@login_required
def admin_clear_data():
    clear_type = request.form.get('clear_type', '')
    db = get_db()

    # Destructive and irreversible: re-confirm with the current admin password (a stolen or left-open
    # session alone is not enough to wipe a shop). Failures are rate-limited like a normal login.
    rl_key = f"cleardata:{g.tenant_slug}:{client_ip()}"
    if ratelimit.seconds_locked(rl_key):
        flash('Too many wrong passwords. Please wait a few minutes and try again.', 'error')
        return redirect(url_for('admin_settings'))
    stored = (get_setting('admin_password', '') or '').strip()
    if not verify_password(request.form.get('confirm_password', ''), stored):
        ratelimit.record_failure(rl_key)
        flash('Wrong password. Nothing was deleted.', 'error')
        return redirect(url_for('admin_settings'))
    ratelimit.clear(rl_key)

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

def _csv_safe(value):
    """Stop spreadsheet formula injection: customer-typed text such as '=HYPERLINK(...)' must stay text."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in ('=', '@', '\t', '\r'):
        return "'" + value
    if value[0] in ('+', '-') and not re.fullmatch(r'[+\-][0-9 ().\-]+', value):
        return "'" + value          # '+91 98765 43210' (a phone number) is left alone
    return value

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
            writer.writerow([_csv_safe(v) for v in (p['id'], p['name'], p['category'], p['price'], p['stock'], p['size'], p['created_at'])])
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
            writer.writerow([_csv_safe(v) for v in (o['id'], o['customer_name'], o['phone'], o['address'], o['total'], o['status'], o['created_at'])])
        filename = f"{g.tenant_slug}_orders_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    else:
        flash('Invalid export type requested.', 'error')
        return redirect(url_for('admin_dashboard'))

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
