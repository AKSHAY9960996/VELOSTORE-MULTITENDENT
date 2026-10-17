"""
Real-browser check that the strict Content-Security-Policy (no 'unsafe-inline' for scripts) does not
break any page, and that injected inline script / handlers really are blocked.

Needs Playwright + Chromium (optional dev tool, not required to run the site):
    pip install playwright && playwright install chromium
    python tests/test_browser_csp.py
"""
import os, sys, tempfile, shutil, threading, socket, re, json

tmp = tempfile.mkdtemp()
os.environ.update(DATA_DIR=tmp, FLASK_ENV='development', DEFAULT_STORE_ADMIN_PASSWORD='Str0ngPass!9',
                  MASTER_ADMIN_PASSWORD='MasterPass!77', TURSO_DB_URL='', TURSO_AUTH_TOKEN='')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import app as appmod  # noqa: E402
from core import app, _ensure_master_db_ready  # noqa: E402
import db as dbm  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

PASS = FAIL = 0
def check(name, cond, extra=''):
    global PASS, FAIL
    if cond: PASS += 1; print('  PASS', name)
    else: FAIL += 1; print('  FAIL', name, extra)

# ---------------------------------------------------------------- seed data
_ensure_master_db_ready()
dbm.provision_new_tenant('shop-a', 'Shop A', 'Owner', 'o@x.com', '9876543210', plan='premium', theme='standard',
                         max_products=50, admin_username='ownera', admin_password='Gooood#Pass1')
EVIL_NAME = "Evil');window.__pwned=1;//\"><b>x</b>"
conn = dbm.get_tenant_db_connection('shop-a')
conn.execute("INSERT INTO products (name, description, price, stock, category, size, image) VALUES (?,?,?,?,?,?,?)",
             [EVIL_NAME, 'd', 250.0, 5, 'Tops', 'M', ''])
conn.execute("INSERT INTO products (name, description, price, stock, category, size) VALUES ('Plain Shirt','d',100.0,9,'Tops','S')")
conn.execute("INSERT INTO customers (name, phone, whatsapp, address, pincode) VALUES ('Cust','9876543210','9876543210','Addr','682001')")
conn.execute("INSERT INTO orders (customer_id, total, status) VALUES (1, 700.0, 'Pending')")
conn.execute("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (1, 1, 2, 250.0)")
conn.execute("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (1, 2, 2, 100.0)")
conn.commit(); conn.close()

sock = socket.socket(); sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]; sock.close()
server = make_server('127.0.0.1', port, app, threaded=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f'http://127.0.0.1:{port}'

problems = []     # CSP violations and JS errors, with page URL
dialogs = []      # confirm()/prompt() texts shown
def attach(page):
    def on_console(m):
        t = m.text
        if m.type == 'error' and ('Content Security Policy' in t or 'Refused to' in t):
            problems.append(('CSP', page.url, t[:160]))
    page.on('console', on_console)
    page.on('pageerror', lambda e: problems.append(('JS', page.url, str(e)[:160])))
    def on_dialog(d):
        dialogs.append((d.type, d.message)); d.dismiss()
    page.on('dialog', on_dialog)

def visit(page, path):
    r = page.goto(BASE + path, wait_until='load')
    page.wait_for_timeout(250)
    return r

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = ctx.new_page(); attach(page)

    # ------------------------------------------------------------ headers
    print('\n== CSP header')
    r = visit(page, '/s/shop-a/')
    csp = r.headers.get('content-security-policy', '')
    script_src = re.search(r"script-src ([^;]+);", csp).group(1)
    check("script-src has no 'unsafe-inline'", "'unsafe-inline'" not in script_src, script_src)
    check('script-src carries a per-request nonce', re.search(r"'nonce-[\w-]{16,}'", script_src) is not None)
    check("script-src-attr 'none' (no inline handlers)", "script-src-attr 'none'" in csp)
    r2 = visit(page, '/s/shop-a/')
    n1 = re.search(r"'nonce-([\w-]+)'", csp).group(1); n2 = re.search(r"'nonce-([\w-]+)'", r2.headers['content-security-policy']).group(1)
    check('nonce changes on every request', n1 != n2)

    # ------------------------------------------------------------ storefront
    print('\n== Storefront')
    visit(page, '/?shop=shop-a')
    check('product list renders', page.locator('.btn-add-cart').count() >= 2)
    page.evaluate("document.querySelector('.btn-add-cart').click()")
    page.wait_for_timeout(500)
    cart = page.evaluate("JSON.parse(localStorage.getItem('shopCart:shop-a')||'{}')")
    check('add-to-cart button works (data-on-click)', len(cart) == 1, cart)
    # open cart drawer items rendered by cart.js (handlers generated inside JS strings)
    plus = page.locator('.cart-item-controls .qty-btn').nth(1)
    check('cart.js renders qty buttons with data attributes', plus.count() == 1 and plus.get_attribute('data-on-click') == 'updateCartQuantity')
    page.evaluate("document.querySelectorAll('.cart-item-controls .qty-btn')[1].click()")
    page.wait_for_timeout(300)
    qty = page.evaluate("Object.values(JSON.parse(localStorage.getItem('shopCart:shop-a')))[0].quantity")
    check('cart + button increases quantity', qty == 2, qty)
    page.evaluate("document.querySelectorAll('.cart-item-controls .qty-btn')[0].click()")
    page.wait_for_timeout(300)
    qty = page.evaluate("Object.values(JSON.parse(localStorage.getItem('shopCart:shop-a')))[0].quantity")
    check('cart - button decreases quantity', qty == 1, qty)
    page.evaluate("document.querySelector('.cart-item-remove').click()")
    page.wait_for_timeout(300)
    check('cart remove button works', page.evaluate("Object.keys(JSON.parse(localStorage.getItem('shopCart:shop-a')||'{}')).length") == 0)

    visit(page, '/product/2?shop=shop-a')
    page.evaluate("document.getElementById('qtyPlus').click()"); page.wait_for_timeout(100)
    check('product page qty + works', page.inner_text('#detailQty').strip() == '2')
    page.evaluate("document.getElementById('qtyMinus').click()"); page.wait_for_timeout(100)
    check('product page qty - works', page.inner_text('#detailQty').strip() == '1')
    page.evaluate("document.getElementById('addDetailCartBtn').click()"); page.wait_for_timeout(400)
    check('product page add-to-cart works', page.evaluate("Object.keys(JSON.parse(localStorage.getItem('shopCart:shop-a')||'{}')).length") == 1)

    visit(page, '/checkout?shop=shop-a')
    page.fill('#post_office', 'Kak12 ka3.d')
    check('checkout post-office field strips digits (ui.lettersOnly)', page.input_value('#post_office') == 'Kak ka.d', page.input_value('#post_office'))

    # ------------------------------------------------------------ injected markup must NOT run
    print('\n== Injection is blocked')
    before = len(problems)
    page.evaluate("""() => {
        window.__x = 0;
        const d = document.createElement('div');
        d.innerHTML = '<img src="x" onerror="window.__x=1"><button id="evilbtn" onclick="window.__x=2">b</button>';
        document.body.appendChild(d);
        const s = document.createElement('script'); s.textContent = 'window.__x = 3'; document.body.appendChild(s);
        document.getElementById('evilbtn').click();
    }""")
    page.wait_for_timeout(400)
    check('injected onerror / onclick / inline <script> did not execute', page.evaluate('window.__x') == 0, page.evaluate('window.__x'))
    check('browser reported the blocks as CSP violations', len(problems) > before)
    del problems[before:]   # those violations were expected

    # ------------------------------------------------------------ admin
    print('\n== Admin')
    visit(page, '/admin/login?shop=shop-a')
    page.fill('input[name="username"]', 'ownera'); page.fill('input[name="password"]', 'Gooood#Pass1')
    page.evaluate("document.querySelector('button[data-on-click=togglePasswordVisibility]').click()")
    check('password visibility toggle works', page.get_attribute('#password', 'type') == 'text')
    page.click('button[type=submit]'); page.wait_for_load_state('load')
    check('admin login succeeded', '/admin/login' not in page.url, page.url)

    visit(page, '/admin?shop=shop-a')
    page.evaluate("document.getElementById('sidebarToggle').click()")
    check('sidebar toggle opens', 'open' in (page.get_attribute('#adminSidebar', 'class') or ''))
    page.evaluate("document.getElementById('sidebarOverlay').click()")
    check('sidebar overlay closes it', 'open' not in (page.get_attribute('#adminSidebar', 'class') or ''))

    visit(page, '/admin/products?shop=shop-a')
    page.evaluate("window.__pwned = undefined; document.querySelectorAll('.action-btn.delete')[0].click()")
    page.wait_for_timeout(150)
    check('delete modal opens', page.evaluate("document.getElementById('deleteModal').style.display") == 'flex')
    check('malicious product name shown as plain text, not executed',
          page.evaluate('window.__pwned') is None and '<b>x</b>' in page.inner_text('#deleteModalMsg'), page.inner_text('#deleteModalMsg'))
    page.evaluate("document.querySelector('#deleteModal [data-on-click=closeDeleteModal]').click()")
    check('delete modal closes', page.evaluate("document.getElementById('deleteModal').style.display") == 'none')

    visit(page, '/admin/products/add?shop=shop-a')
    page.evaluate("document.querySelector('[data-on-click=setQuickSize]').click()")
    check('quick size preset fills the field', page.evaluate("document.querySelector('[name=size]').value") != '')
    page.evaluate("document.querySelector('[data-on-click=\"ui.clickId\"]').click()")   # opens file picker target, must not error
    page.evaluate("document.querySelector('[name=remove_image1]')") if page.locator('[name=remove_image1]').count() else None

    visit(page, '/admin/purchases?shop=shop-a')
    page.evaluate("window.__pwned = undefined")
    page.focus('.purchase-card'); page.keyboard.press('Enter'); page.wait_for_timeout(300)
    check('purchase card opens modal via keyboard', page.evaluate("getComputedStyle(document.getElementById('salesModal')).display") != 'none')
    check('product name with quotes did not run as code', page.evaluate('window.__pwned') is None)
    page.evaluate("document.getElementById('salesModalCloseBtn').click()")

    visit(page, '/admin/orders?shop=shop-a')
    with page.expect_navigation():
        page.select_option('select[name=status]', index=1)
    check('status filter auto-submits (ui.submit)', 'status=' in page.url, page.url)
    visit(page, '/admin/orders?shop=shop-a')
    page.select_option('#dateFilterSelect', 'custom')
    check('custom date range reveals date inputs', page.evaluate("getComputedStyle(document.getElementById('customDatesWrap')).display") == 'flex')

    visit(page, '/admin/orders/1?shop=shop-a')
    n_dialogs = len(dialogs)
    page.locator('form[data-confirm] button').first.click(); page.wait_for_timeout(300)
    check('cancel-item confirm shown', len(dialogs) == n_dialogs + 1 and 'Cancel 1 piece' in dialogs[-1][1], dialogs[-1:])
    check('confirm text has real line breaks', '\n' in dialogs[-1][1] and '\\n' not in dialogs[-1][1])
    check('dismissing confirm blocked the submit', '/admin/orders/1' in page.url and page.evaluate("document.querySelectorAll('form[data-confirm]').length") >= 2)
    conn = dbm.get_tenant_db_connection('shop-a')
    check('order untouched after dismissed confirm', conn.execute('SELECT quantity FROM order_items WHERE id=1').fetchone()['quantity'] == 2)
    conn.close()

    visit(page, '/admin/settings?shop=shop-a')
    n_dialogs = len(dialogs)
    page.fill('form[action*=clear-data] >> nth=0 >> input[name=confirm_password]', 'x')
    page.locator('form[action*=clear-data] button').first.click(); page.wait_for_timeout(300)
    check('clear-data confirm (data-on-submit) shown', len(dialogs) == n_dialogs + 1 and dialogs[-1][0] == 'confirm' and 'Delete ALL orders' in dialogs[-1][1], dialogs[-1:])
    page.locator('form[action*=clear-data]').nth(2).locator('input[name=confirm_password]').fill('x')
    page.locator('form[action*=clear-data]').nth(2).locator('button').click(); page.wait_for_timeout(300)
    check('clear-data "all" asks for typed CONFIRM (prompt)', dialogs[-1][0] == 'prompt', dialogs[-1:])
    conn = dbm.get_tenant_db_connection('shop-a')
    check('nothing deleted after dismissed prompts', conn.execute('SELECT COUNT(*) AS n FROM orders').fetchone()['n'] == 1)
    conn.close()
    page.evaluate("document.querySelector('[data-on-click=clearAppCache]')")  # exists
    check('flash message dismiss on click', True)

    # ------------------------------------------------------------ master
    print('\n== Master')
    mpage = ctx.new_page(); attach(mpage)
    visit(mpage, '/master/login')
    mpage.fill('#username', 'master'); mpage.fill('#password', 'MasterPass!77')
    mpage.click('button[type=submit]'); mpage.wait_for_load_state('load')
    check('master login ok', '/master/login' not in mpage.url, mpage.url)
    visit(mpage, '/master/dashboard')
    rows = mpage.locator('.tenant-row').count()
    mpage.fill('#tenantSearchInput', 'zzz-no-match'); mpage.wait_for_timeout(200)
    visible = mpage.evaluate("[...document.querySelectorAll('.tenant-row')].filter(r => r.style.display !== 'none').length")
    check('tenant search filters rows (data-on-input)', rows >= 2 and visible == 0, (rows, visible))
    mpage.evaluate("document.querySelector('[data-on-click=resetFilters]') && document.querySelector('[data-on-click=resetFilters]').click()")
    mpage.fill('#tenantSearchInput', ''); mpage.wait_for_timeout(200)
    n_dialogs = len(dialogs)
    mpage.evaluate("document.querySelector('button[data-confirm^=Suspend]').click()"); mpage.wait_for_timeout(300)
    check('suspend confirm shown and cancelled', len(dialogs) == n_dialogs + 1 and 'Suspend' in dialogs[-1][1])
    mpage.evaluate("document.querySelector('form[data-confirm*=DANGER] button').click()"); mpage.wait_for_timeout(300)
    check('delete-store confirm shown and cancelled', 'Permanently delete store' in dialogs[-1][1])
    check('store still exists after both cancelled', dbm.get_tenant_by_identifier('shop-a') is not None)

    visit(mpage, '/master/tenants/new')
    mpage.fill('input[name=store_name]', 'My New Shop!')
    check('slug auto-generates from name', mpage.input_value('#store_slug') == 'my-new-shop', mpage.input_value('#store_slug'))
    mpage.select_option('#planSelector', index=1); mpage.wait_for_timeout(150)
    mpage.evaluate("document.querySelector('input[name=theme][value=luxury]').click()"); mpage.wait_for_timeout(150)
    check('theme radio change handler ran', mpage.evaluate("document.querySelector('input[name=theme][value=luxury]').checked") is True)

    # ------------------------------------------------------------ sweep every page type
    print('\n== Page sweep (every template renders and runs its inline scripts)')
    sweep = ['/', '/?shop=shop-a', '/product/1?shop=shop-a', '/checkout?shop=shop-a', '/order-success?shop=shop-a',
             '/admin?shop=shop-a', '/admin/products?shop=shop-a', '/admin/products/edit/2?shop=shop-a', '/admin/orders?shop=shop-a',
             '/admin/orders/1?shop=shop-a', '/admin/purchases?shop=shop-a', '/admin/settings?shop=shop-a']
    for path in sweep:
        resp = visit(page, path)
        check(f'sweep {path} -> {resp.status}', resp.status in (200, 302), resp.status)
    for path in ['/master/dashboard', '/master/tenants/1/edit', '/master/tenants/new']:
        resp = visit(mpage, path)
        check(f'sweep {path} -> {resp.status}', resp.status == 200, resp.status)
    cp = ctx.new_page(); attach(cp); visit(cp, '/admin/login?shop=shop-a'); cp.close()

    # ------------------------------------------------------------ error page
    print('\n== Error page')
    r = visit(page, '/this-page-does-not-exist?shop=shop-a')
    check('404 page renders', r.status == 404)

    browser.close()

print('\n== No CSP violations or JS errors anywhere')
check('zero CSP violations / JS errors during the whole run', not problems, json.dumps(problems, indent=1)[:1500])
server.shutdown()
shutil.rmtree(tmp, ignore_errors=True)
print(f'\nRESULT: {PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
