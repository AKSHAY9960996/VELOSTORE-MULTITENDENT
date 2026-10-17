import os, re, sys, tempfile, shutil, threading, importlib
tmp = tempfile.mkdtemp()
os.environ.update(DATA_DIR=tmp, FLASK_ENV='development', DEFAULT_STORE_ADMIN_PASSWORD='Str0ngPass!9',
                  TURSO_DB_URL='', TURSO_AUTH_TOKEN='')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod
from core import app
app.config['TESTING'] = False

PASS = FAIL = 0
def check(name, cond, extra=''):
    global PASS, FAIL
    if cond: PASS += 1; print('  PASS', name)
    else: FAIL += 1; print('  FAIL', name, extra)

def token(client, path='/admin/login?shop=default'):
    r = client.get(path)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True))
    return m.group(1) if m else None

def new_client():
    return app.test_client()

print('\n== Headers / landing')
c = new_client()
r = c.get('/')
check('landing 200', r.status_code == 200)
for h in ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy']:
    check(f'header {h}', h in r.headers)

print('\n== CSRF')
c = new_client()
r = c.post('/master/login', data={'username': 'master', 'password': 'master123'})
check('POST without token -> 400', r.status_code == 400, r.status_code)
t = token(c, '/master/login')
check('token present on master login form', bool(t))
r = c.post('/master/login', data={'username': 'master', 'password': 'master123', 'csrf_token': 'wrong'})
check('POST wrong token -> 400', r.status_code == 400)
r = c.post('/master/login', data={'username': 'master', 'password': 'master123', 'csrf_token': t},
           headers={'Origin': 'https://evil.example'})
check('POST right token but foreign Origin -> 400', r.status_code == 400)
r = c.post('/master/login', data={'username': 'master', 'password': 'master123', 'csrf_token': t})
check('master login with token -> 302', r.status_code == 302, r.status_code)
master = c

print('\n== /diag gating')
check('diag anonymous -> 404', new_client().get('/diag').status_code == 404)
check('diag master -> 200', master.get('/diag').status_code == 200)
check('diag has no URL prefix leak', 'TURSO_DB_URL_prefix' not in master.get('/diag').get_data(as_text=True))

print('\n== Provisioning validation')
def provision(slug, pw, user='shopowner'):
    t = token(master, '/master/tenants/new')
    return master.post('/master/tenants/new', data=dict(csrf_token=t, store_name='T '+slug, slug=slug, owner_name='O',
        owner_email='o@x.com', owner_phone='9876543210', plan='basic', theme='standard', max_products='50',
        admin_username=user, admin_password=pw, flag_export_csv='on'), follow_redirects=True).get_data(as_text=True)
check('slug ../evil rejected', 'Store identifier must be' in provision('../evil', 'Gooood#Pass1'))
check('reserved slug rejected', 'reserved' in provision('admin', 'Gooood#Pass1'))
check('weak password rejected', 'at least 8' in provision('shop-a', 'abc'))
check('common password rejected', 'too common' in provision('shop-a', 'admin123'))
check('empty password rejected', 'at least 8' in provision('shop-a', ''))
out = provision('shop-a', 'Gooood#Pass1', 'ownera')
check('valid tenant provisioned', 'successfully provisioned' in out, out[:200])
out = provision('shop-b', 'Gooood#Pass2', 'ownerb')
check('second tenant provisioned', 'successfully provisioned' in out)

print('\n== Impersonation is POST only')
check('GET login-as -> 405', master.get('/master/tenants/2/login-as').status_code == 405)

print('\n== Admin login + rate limit (DB-backed, XFF spoof-proof)')
def admin_login(client, shop, user, pw, xff=None):
    t = token(client, f'/admin/login?shop={shop}')
    h = {'X-Forwarded-For': xff} if xff else {}
    return client.post(f'/admin/login?shop={shop}', data=dict(csrf_token=t, username=user, password=pw, shop_slug=shop), headers=h)
c = new_client()
for i in range(5):
    r = admin_login(c, 'shop-a', 'ownera', 'wrong-pass', xff=f'9.9.9.{i}, 1.2.3.4')   # spoofed first hop each time
r = admin_login(c, 'shop-a', 'ownera', 'Gooood#Pass1', xff='7.7.7.7, 1.2.3.4')
check('locked after 5 failures even with rotating spoofed XFF', r.status_code == 429, r.status_code)
c2 = new_client()
r = admin_login(c2, 'shop-b', 'ownerb', 'Gooood#Pass2', xff='5.5.5.5, 1.2.3.4')
check('same real IP stays locked for other store too', r.status_code == 429)
# lockout is in the DB: reload modules and confirm it persists ("restart")
from ratelimit import seconds_locked
check('lockout persisted in DB (survives restart)', seconds_locked('admin-ip:1.2.3.4') > 0)
# clear it and log in properly from a different IP
import ratelimit; ratelimit.clear('admin-ip:1.2.3.4', 'admin-store:shop-a', 'admin-store:shop-b')
c = new_client()
r = admin_login(c, 'shop-a', 'ownera', 'Gooood#Pass1')
check('correct login after unlock -> 302', r.status_code == 302, r.status_code)
shop_a = c

print('\n== Master login lockout')
mc = new_client()
for i in range(5):
    t = token(mc, '/master/login'); mc.post('/master/login', data=dict(csrf_token=t, username='master', password='bad'))
t = token(mc, '/master/login')
r = mc.post('/master/login', data=dict(csrf_token=t, username='master', password='master123'))
check('master locked after 5 failures', r.status_code == 429, r.status_code)
ratelimit.clear('master:127.0.0.1', 'master-user:master')

print('\n== Redirect hardening')
r = new_client().get('/s/shop-a/admin/orders')
check('/s/shop-a/admin/orders -> /admin/orders?shop=shop-a', r.headers.get('Location') == '/admin/orders?shop=shop-a', r.headers.get('Location'))
for bad in ['admin/../../evil.com', 'admin/%2e%2e/%2e%2e/evil.com', 'admin//evil.com', 'admin/nope/doesnotexist', 'admin/orders%3Fx%3D1']:
    r = new_client().get('/s/shop-a/' + bad)
    loc = r.headers.get('Location', '')
    check(f'bad path {bad!r} -> dashboard/safe', 'evil' not in loc and loc.startswith(('/admin?shop=shop-a', '/admin?')) or r.status_code == 404, loc)

print('\n== Admin product validation + CSRF on delete')
def add_product(client, **kw):
    t = token(client, '/admin/products/add?shop=shop-a')
    data = dict(csrf_token=t, name='Shirt', description='d', price='100', stock='1', category='c', size='M'); data.update(kw)
    return client.post('/admin/products/add?shop=shop-a', data=data, follow_redirects=True).get_data(as_text=True)
check('negative price rejected', 'Price must be' in add_product(shop_a, price='-5'))
check('non-numeric price rejected (no 500)', 'Price must be a number' in add_product(shop_a, price='abc'))
check('negative stock rejected', 'Stock must be' in add_product(shop_a, stock='-1'))
check('valid product added', 'added successfully' in add_product(shop_a))
r = shop_a.post('/admin/products/delete/1?shop=shop-a')
check('delete without CSRF token -> 400', r.status_code == 400)

print('\n== Checkout hardening')
sf = new_client()
sf.get('/?shop=shop-a')
def checkout(client, pids, qtys, **over):
    t = token(client, '/checkout?shop=shop-a')
    data = {'csrf_token': t, 'product_id[]': pids, 'quantity[]': qtys, 'name': 'Cust', 'phone': '9876543210', 'whatsapp': '9876543210',
            'address': 'Addr', 'post_office': 'PO', 'district': 'Ekm', 'pincode': '682001'}
    data.update(over)
    return client.post('/checkout?shop=shop-a', data=data, headers={'Accept': 'application/json'})
r = checkout(sf, ['1'], ['-5'])
check('negative quantity rejected', r.get_json()['success'] is False, r.get_json())
r = checkout(sf, ['1'], ['999999'])
check('huge quantity rejected', r.get_json()['success'] is False)
r = checkout(sf, ['1', '1'], ['1', '1'])
check('duplicate lines merged: 2 > stock 1 rejected', r.get_json()['success'] is False and 'left in stock' in r.get_json()['error'], r.get_json())
r = checkout(sf, ['abc'], ['1'])
check('non-numeric id -> clean error not 500', r.status_code == 200 and r.get_json()['success'] is False)
r = checkout(sf, ['1'], ['1'], pincode='12')
check('bad pincode rejected', r.get_json()['success'] is False)
r = checkout(sf, ['1'], ['1'], phone='<script>')
check('bad phone rejected', r.get_json()['success'] is False)
r = checkout(sf, ['1'], ['1'], notes='x'*301)
check('over-long notes rejected', r.get_json()['success'] is False)
r = sf.post('/checkout?shop=shop-a', data={'product_id[]': ['1'], 'quantity[]': ['1']})
check('checkout without CSRF -> 400 JSON', r.status_code == 400 and r.get_json()['success'] is False)
r = checkout(sf, ['1'], ['1'], notes='gift please')
check('valid checkout succeeds', r.get_json()['success'] is True, r.get_json())
page = sf.get('/order-success?shop=shop-a').get_data(as_text=True)
check('order success page renders WhatsApp message from DB', 'wa.me/' in page and 'gift%20please' in page)
sf2 = new_client(); sf2.get('/?shop=shop-a')
r = checkout(sf2, ['1'], ['1'])
check('last item cannot be sold twice', r.get_json()['success'] is False)
# stock never negative
import db as dbm
conn = dbm.get_tenant_db_connection('shop-a'); st = conn.execute('SELECT stock FROM products WHERE id=1').fetchone()['stock']; conn.close()
check('stock is exactly 0 (not negative)', st == 0, st)

print('\n== Parallel race on last item')
shop_a.post('/admin/products/edit/1?shop=shop-a', data=dict(csrf_token=token(shop_a, '/admin/products/edit/1?shop=shop-a'), name='Shirt', description='d', price='100', stock='3', category='c', size='M'))
results = []
def worker():
    cl = new_client(); cl.get('/?shop=shop-a')
    t = token(cl, '/checkout?shop=shop-a')
    r = cl.post('/checkout?shop=shop-a', data={'csrf_token': t, 'product_id[]': ['1'], 'quantity[]': ['1'], 'name': 'C', 'phone': '9876543210',
        'whatsapp': '9876543210', 'address': 'A', 'post_office': 'P', 'district': 'D', 'pincode': '682001'})
    results.append(r.get_json()['success'])
ths = [threading.Thread(target=worker) for _ in range(8)]
[t.start() for t in ths]; [t.join() for t in ths]
conn = dbm.get_tenant_db_connection('shop-a'); st = conn.execute('SELECT stock FROM products WHERE id=1').fetchone()['stock']; conn.close()
check(f'8 parallel buyers, stock 3 -> exactly 3 succeed (got {sum(results)})', sum(results) == 3, results)
check('stock ends at 0, never negative', st == 0, st)

print('\n== Order status validation')
t = token(shop_a, '/admin/orders/1?shop=shop-a')
r = shop_a.post('/admin/orders/1/status?shop=shop-a', data=dict(csrf_token=t, status='<b>Hacked</b>'), follow_redirects=True)
check('invalid status rejected', 'Invalid order status' in r.get_data(as_text=True))
conn = dbm.get_tenant_db_connection('shop-a'); before = conn.execute('SELECT stock FROM products WHERE id=1').fetchone()['stock']; conn.close()
r = shop_a.post('/admin/orders/1/status?shop=shop-a', data=dict(csrf_token=t, status='Cancelled'), follow_redirects=True)
conn = dbm.get_tenant_db_connection('shop-a'); after = conn.execute('SELECT stock FROM products WHERE id=1').fetchone()['stock']; conn.close()
check('cancelling restores stock once', after == before + 1, (before, after))
r = shop_a.post('/admin/orders/1/status?shop=shop-a', data=dict(csrf_token=t, status='Cancelled'), follow_redirects=True)
conn = dbm.get_tenant_db_connection('shop-a'); after2 = conn.execute('SELECT stock FROM products WHERE id=1').fetchone()['stock']; conn.close()
check('repeat cancel does NOT restore stock again', after2 == after, (after, after2))

print('\n== Settings password change')
def settings_post(client, **kw):
    t = token(client, '/admin/settings?shop=shop-a')
    data = dict(csrf_token=t, shop_name='S', whatsapp_number='9876543210', currency_symbol='₹', currency_code='INR', show_out_of_stock='1',
                stock_reduction_mode='reserve', reservation_minutes='15'); data.update(kw)
    return client.post('/admin/settings?shop=shop-a', data=data, follow_redirects=True).get_data(as_text=True)
check('change without current password blocked', 'current password is incorrect' in settings_post(shop_a, admin_password='NewPassw0rd!', confirm_password='NewPassw0rd!'))
check('weak new password blocked', 'at least 8' in settings_post(shop_a, current_password='Gooood#Pass1', admin_password='short', confirm_password='short'))
check('mismatch blocked', 'do not match' in settings_post(shop_a, current_password='Gooood#Pass1', admin_password='NewPassw0rd!', confirm_password='Different1!'))
out = settings_post(shop_a, current_password='Gooood#Pass1', admin_password='NewPassw0rd!', confirm_password='NewPassw0rd!')
check('valid change works', 'updated securely' in out)

print('\n== CSV formula injection')
# create product with formula-looking name, export (basic plan has export_csv)
shop_a2 = new_client(); r = admin_login(shop_a2, 'shop-a', 'ownera', 'NewPassw0rd!')
add_product(shop_a2, name='=HYPERLINK("http://evil","x")', stock='5')
r = shop_a2.get('/admin/export/products?shop=shop-a')
csv_text = r.get_data(as_text=True)
check('formula cell neutralised', "'=HYPERLINK" in csv_text and '\n1,=HYPER' not in csv_text, csv_text[:200])
check('Content-Disposition quoted', 'filename="' in r.headers.get('Content-Disposition', ''))

print('\n== Clear-data needs the admin password')
def clear_post(client, pw, kind='orders'):
    t = token(client, '/admin/settings?shop=shop-a')
    return client.post('/admin/clear-data?shop=shop-a', data=dict(csrf_token=t, clear_type=kind, confirm_password=pw),
                       follow_redirects=True).get_data(as_text=True)
import db as _db
def order_count():
    c = _db.get_tenant_db_connection('shop-a'); n = c.execute('SELECT COUNT(*) AS n FROM orders').fetchone()['n']; c.close(); return n
before = order_count()
check('settings page shows password box on clear forms', 'name="confirm_password"' in shop_a2.get('/admin/settings?shop=shop-a').get_data(as_text=True))
check('clear with no/wrong password is refused', 'Wrong password' in clear_post(shop_a2, 'nope'))
check('orders untouched after wrong password', order_count() == before)
for i in range(5): clear_post(shop_a2, 'nope')
check('repeated wrong passwords get locked out', 'Too many wrong passwords' in clear_post(shop_a2, 'NewPassw0rd!'))
_c = _db.get_master_db_connection(); _c.execute("DELETE FROM login_attempts WHERE key LIKE 'cleardata:%'"); _c.commit(); _c.close()
check('correct password clears orders', 'have been deleted' in clear_post(shop_a2, 'NewPassw0rd!'))
check('orders really gone', order_count() == 0)

print('\n== Turso tokens encrypted at rest')
secret = 'tok_abc.DEF-123'
enc = _db.encrypt_token(secret)
check('encrypted value is not the plain token', enc.startswith('enc1:') and secret not in enc)
check('round-trips', _db.decrypt_token(enc) == secret)
check('encrypting twice is a no-op', _db.encrypt_token(enc) == enc)
check('legacy plain-text value still readable', _db.decrypt_token(secret) == secret)
mc = _db.get_master_db_connection()
mc.execute("INSERT INTO tenants (slug, store_name, owner_name, turso_db_url, turso_auth_token) VALUES ('legacy-tok','L','O','libsql://x',?)", [secret]); mc.commit()
_db.encrypt_plaintext_tenant_tokens(mc)
raw = mc.execute("SELECT turso_auth_token FROM tenants WHERE slug='legacy-tok'").fetchone()['turso_auth_token']; mc.close()
check('startup migration encrypts existing plain-text tokens', raw.startswith('enc1:') and _db.decrypt_token(raw) == secret)
_old = os.environ.get('TOKEN_ENCRYPTION_KEY'); os.environ['TOKEN_ENCRYPTION_KEY'] = 'a-different-key-entirely'; _db._fernet_cache = None
try:
    _db.decrypt_token(enc); wrong_key_fails = False
except RuntimeError:
    wrong_key_fails = True
check('wrong key fails loudly (no silent fallback)', wrong_key_fails)
if _old is None: os.environ.pop('TOKEN_ENCRYPTION_KEY')
else: os.environ['TOKEN_ENCRYPTION_KEY'] = _old
_db._fernet_cache = None

print('\n== Admin usernames live in the master table (unique, indexed)')
def master_user(slug):
    c = _db.get_master_db_connection(); r = c.execute('SELECT admin_username FROM tenants WHERE slug=?', [slug]).fetchone(); c.close()
    return r['admin_username'] if r else None
def master_exec(sql, args=()):
    c = _db.get_master_db_connection()
    try:
        cur = c.execute(sql, list(args)); c.commit(); return cur
    except Exception:
        c.rollback(); raise
    finally:
        c.close()
# the fake store created by the token test has no database; remove it so it doesn't look like a pending store
master_exec("DELETE FROM tenants WHERE slug='legacy-tok'")
check('provisioning stored the username in the master table', master_user('shop-a') == 'ownera' and master_user('shop-b') == 'ownerb', (master_user('shop-a'), master_user('shop-b')))
check('default store username backfilled at startup', master_user('default') == 'admin', master_user('default'))
c = _db.get_master_db_connection()
idx = c.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_tenants_admin_username'").fetchone(); c.close()
check('unique index exists (case-insensitive)', idx is not None and 'UNIQUE' in idx['sql'].upper() and 'lower(' in idx['sql'], idx['sql'] if idx else None)
# the database itself refuses duplicates, even if application code were bypassed
try:
    master_exec("UPDATE tenants SET admin_username='OwnerA' WHERE slug='shop-b'"); dup_ok = True
except Exception:
    dup_ok = False
check('DB refuses a case-variant duplicate username', dup_ok is False and master_user('shop-b') == 'ownerb')

# fast path: with everything stored, no store database is opened at all
_calls = []
_orig_conn = _db.get_tenant_db_connection
_db.get_tenant_db_connection = lambda slug: (_calls.append(slug), _orig_conn(slug))[1]
t1 = _db.is_admin_username_taken('OWNERA'); t2 = _db.is_admin_username_taken('nobody-uses-this'); t3 = _db.is_admin_username_taken('ownera', exclude_slug='shop-a')
check('taken name found case-insensitively', t1 is True)
check('unused name is free; own name is free for yourself', t2 is False and t3 is False)
check('check opens ZERO store databases (was one per store)', _calls == [], _calls)
_db.get_tenant_db_connection = _orig_conn

out = provision('shop-c', 'Gooood#Pass3', 'OWNERA')
check('provisioning with a taken username (other case) is refused', 'already used by another store' in out, out[:200])
check('refused store was not created', _db.get_tenant_by_identifier('shop-c') is None)

# renaming through the store settings page
out = settings_post(shop_a2, admin_username='ownerb', current_password='NewPassw0rd!')
check('shop-a cannot take shop-b\'s username', 'already used by another store' in out and master_user('shop-a') == 'ownera')
out = settings_post(shop_a2, admin_username='ownera-new', current_password='NewPassw0rd!')
check('rename succeeds', master_user('shop-a') == 'ownera-new', master_user('shop-a'))
_c = _db.get_tenant_db_connection('shop-a'); inner = _c.execute("SELECT value FROM settings WHERE key='admin_username'").fetchone()['value']; _c.close()
check('store settings and master table agree', inner == 'ownera-new', inner)
check('old name is free again, new name is taken', _db.is_admin_username_taken('ownera') is False and _db.is_admin_username_taken('OWNERA-NEW') is True)
settings_post(shop_a2, admin_username='ownera', current_password='NewPassw0rd!')
check('renamed back', master_user('shop-a') == 'ownera')

# master "edit store" page
def master_edit(tid, user):
    t = token(master, f'/master/tenants/{tid}/edit')
    return master.post(f'/master/tenants/{tid}/edit', data=dict(csrf_token=t, store_name='T', owner_name='O', owner_email='o@x.com',
        owner_phone='9876543210', plan='basic', theme='standard', max_products='50', is_active='on', admin_username=user), follow_redirects=True).get_data(as_text=True)
out = master_edit(3, 'ownera')
check('master edit: duplicate username refused and unchanged', 'NOT changed' in out and master_user('shop-b') == 'ownerb')
master_edit(3, 'ownerb-renamed')
check('master edit: rename works', master_user('shop-b') == 'ownerb-renamed')
master_edit(3, 'ownerb')

# suspended stores keep their name reserved
master_exec("UPDATE tenants SET is_active=0 WHERE slug='shop-b'")
check('suspended store keeps its username reserved', _db.is_admin_username_taken('ownerb') is True)
master_exec("UPDATE tenants SET is_active=1 WHERE slug='shop-b'")

# upgrade path: stores that predate the column
master_exec("UPDATE tenants SET admin_username=NULL WHERE slug='shop-b'")
check('un-backfilled store is still protected (falls back to its own DB)', _db.is_admin_username_taken('ownerb') is True)
_db.init_master_db()
check('startup backfill restores the master value', master_user('shop-b') == 'ownerb', master_user('shop-b'))
# legacy duplicate: two stores already sharing a name must not crash startup or the index
_c = _db.get_tenant_db_connection('shop-b'); _c.execute("UPDATE settings SET value='ownera' WHERE key='admin_username'"); _c.commit(); _c.close()
master_exec("UPDATE tenants SET admin_username=NULL WHERE slug='shop-b'")
_db.init_master_db()
check('legacy duplicate: older store keeps the name, newer left empty (no crash)', master_user('shop-a') == 'ownera' and master_user('shop-b') is None)
_c = _db.get_tenant_db_connection('shop-b'); _c.execute("UPDATE settings SET value='ownerb' WHERE key='admin_username'"); _c.commit(); _c.close()
_db.init_master_db()
check('after fixing it, backfill fills it in', master_user('shop-b') == 'ownerb')

# concurrency: two shops racing for the same new name -> exactly one wins
wins = []
def claim(slug):
    try: _db.set_tenant_admin_username(slug, 'race-name'); wins.append(slug)
    except ValueError: pass
ths = [threading.Thread(target=claim, args=(sl,)) for sl in ('shop-a', 'shop-b')]
[t.start() for t in ths]; [t.join() for t in ths]
check('simultaneous claims: exactly one store wins the name', len(wins) == 1, wins)
master_exec("UPDATE tenants SET admin_username='ownera' WHERE slug='shop-a'"); master_exec("UPDATE tenants SET admin_username='ownerb' WHERE slug='shop-b'")
_c = _db.get_tenant_db_connection('shop-a'); _c.execute("UPDATE settings SET value='ownera' WHERE key='admin_username'"); _c.commit(); _c.close()

print('\n== Tenant isolation still holds')
r = shop_a2.get('/admin/products?shop=shop-b')
check('shop-a admin cannot open shop-b admin', r.status_code == 302 and 'login' in r.headers['Location'])

print('\n== Cache-Control on admin')
check('admin pages no-store', 'no-store' in shop_a2.get('/admin?shop=shop-a').headers.get('Cache-Control', ''))

print(f'\nRESULT: {PASS} passed, {FAIL} failed')
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(1 if FAIL else 0)
