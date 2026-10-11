"""Platform (master) admin routes: manage stores, plans, themes and suspensions."""

import json
from db import (
    DEFAULT_PLAN_CONFIG,
    clear_tenant_cache,
    delete_tenant,
    get_master_db_connection,
    get_tenant_db_connection,
    get_tenant_feature_flags,
    provision_new_tenant,
    update_tenant_admin_password,
)
from flask import flash, redirect, render_template, request, session, url_for
from functools import wraps
from security import hash_password, needs_rehash, verify_password
from core import app

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
        m_conn = get_master_db_connection()
        cur = m_conn.cursor()
        cur.execute("SELECT * FROM master_admins WHERE username = ?", [username])
        admin = cur.fetchone()
        if admin and not verify_password(password, admin['password_hash']):
            admin = None
        if admin and needs_rehash(admin['password_hash']):
            # Upgrade legacy SHA-256 hash to a salted hash
            try:
                cur.execute("UPDATE master_admins SET password_hash = ? WHERE id = ?",
                            [hash_password(password), admin['id']])
                m_conn.commit()
            except Exception as e:
                print(f"[Security] could not upgrade master password hash: {e}", flush=True)
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
        clear_tenant_cache()
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
        clear_tenant_cache()
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
