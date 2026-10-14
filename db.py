import os
import json
import sqlite3
import hashlib
import time
from security import hash_password as _hash_password
from collections.abc import Mapping
import requests as _requests

# Try to import official libsql; fall back to sqlite3 for local dev
try:
    import libsql
    HAS_LIBSQL = True
except ImportError:
    try:
        import libsql_experimental as libsql
        HAS_LIBSQL = True
    except ImportError:
        HAS_LIBSQL = False

from config import get_config

_config = get_config()

# ---------------------------------------------------------------------------
# Path constants (used only when Turso is NOT configured / local dev)
# ---------------------------------------------------------------------------
DATA_DIR = os.environ.get('DATA_DIR', os.path.dirname(__file__))
TENANTS_DIR = os.path.join(DATA_DIR, 'tenants_db')
os.makedirs(TENANTS_DIR, exist_ok=True)
MASTER_DB_PATH = os.path.join(DATA_DIR, 'master.db')
DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'database.db')


# ---------------------------------------------------------------------------
# Turso Platform API helpers
# ---------------------------------------------------------------------------

def _turso_api_headers():
    api_token = os.environ.get('TURSO_API_TOKEN', '')
    return {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}


def _turso_is_platform_configured() -> bool:
    return bool(os.environ.get('TURSO_API_TOKEN') and os.environ.get('TURSO_ORG_NAME'))


def _create_turso_tenant_db(slug: str):
    """
    Creates a dedicated Turso database for a tenant via the Turso Platform API.
    Returns (db_url, auth_token) or (None, None) if not configured.
    """
    if not _turso_is_platform_configured():
        return None, None

    org = os.environ.get('TURSO_ORG_NAME')
    db_name = f"vs-{slug}"
    headers = _turso_api_headers()

    try:
        resp = _requests.post(
            f'https://api.turso.tech/v1/organizations/{org}/databases',
            headers=headers,
            json={'name': db_name, 'group': 'default'},
            timeout=20
        )
        if resp.status_code not in (200, 201):
            print(f"[Turso] DB create failed ({resp.status_code}): {resp.text}")
            return None, None

        db_data = resp.json()
        hostname = (
            db_data.get('database', {}).get('Hostname') or
            db_data.get('Hostname') or
            db_data.get('hostname')
        )
        if not hostname:
            print(f"[Turso] No hostname in create response: {db_data}")
            return None, None

        db_url = f"libsql://{hostname}"
    except Exception as e:
        print(f"[Turso] DB create exception: {e}")
        return None, None

    try:
        token_resp = _requests.post(
            f'https://api.turso.tech/v1/organizations/{org}/databases/{db_name}/auth/tokens',
            headers=headers,
            timeout=20
        )
        if token_resp.status_code not in (200, 201):
            print(f"[Turso] Token create failed ({token_resp.status_code}): {token_resp.text}")
            return None, None

        auth_token = token_resp.json().get('jwt')
        if not auth_token:
            print(f"[Turso] No jwt in token response: {token_resp.json()}")
            return None, None
    except Exception as e:
        print(f"[Turso] Token create exception: {e}")
        return None, None

    print(f"[Turso] Created DB for tenant '{slug}': {db_url}")
    return db_url, auth_token


def _delete_turso_tenant_db(slug: str):
    """Deletes a tenant's Turso database via Turso Platform API."""
    if not _turso_is_platform_configured():
        return
    org = os.environ.get('TURSO_ORG_NAME')
    db_name = f"vs-{slug}"
    try:
        resp = _requests.delete(
            f'https://api.turso.tech/v1/organizations/{org}/databases/{db_name}',
            headers=_turso_api_headers(),
            timeout=15
        )
        if resp.status_code in (200, 204):
            print(f"[Turso] Deleted DB for tenant '{slug}'.")
        else:
            print(f"[Turso] DB delete failed ({resp.status_code}): {resp.text}")
    except Exception as e:
        print(f"[Turso] DB delete exception: {e}")


# ---------------------------------------------------------------------------
# Row wrapper & libSQL Connection/Cursor Wrappers
# ---------------------------------------------------------------------------

class TursoRow(Mapping):
    """Dict-like row wrapper for libSQL query results mimicking sqlite3.Row."""

    def __init__(self, columns, values):
        self._columns = list(columns)
        self._values = list(values) if values is not None else []
        self._data = dict(zip(self._columns, self._values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._data[key]

    def __iter__(self):
        return iter(self._columns)

    def __len__(self):
        return len(self._columns)

    def __contains__(self, key):
        return key in self._data

    def keys(self):
        return list(self._columns)

    def values(self):
        return list(self._values)

    def items(self):
        return list(self._data.items())

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __repr__(self):
        return f"TursoRow({self._data})"


def _normalize_params(params):
    if params is None:
        return ()
    if isinstance(params, tuple):
        return params
    if isinstance(params, (list, set)):
        return tuple(params)
    if isinstance(params, dict):
        return params
    return (params,)


class LibsqlCursorWrapper:
    """Wraps a raw libSQL cursor to return TursoRow objects."""

    def __init__(self, raw_cursor):
        self._raw = raw_cursor

    def execute(self, sql, params=None):
        if params is None:
            self._raw.execute(sql)
        else:
            self._raw.execute(sql, _normalize_params(params))
        return self

    def executemany(self, sql, seq_of_params):
        normalized_seq = [_normalize_params(p) for p in seq_of_params]
        self._raw.executemany(sql, normalized_seq)
        return self

    @property
    def description(self):
        return self._raw.description

    @property
    def lastrowid(self):
        return getattr(self._raw, 'lastrowid', None)

    @property
    def rowcount(self):
        return getattr(self._raw, 'rowcount', -1)

    def _wrap_row(self, raw_row):
        if raw_row is None:
            return None
        if self._raw.description:
            columns = [col[0] for col in self._raw.description]
            return TursoRow(columns, raw_row)
        return raw_row

    def fetchone(self):
        return self._wrap_row(self._raw.fetchone())

    def fetchall(self):
        rows = self._raw.fetchall()
        if not rows:
            return []
        if self._raw.description:
            columns = [col[0] for col in self._raw.description]
            return [TursoRow(columns, r) for r in rows]
        return rows

    def fetchmany(self, size=None):
        rows = self._raw.fetchmany(size) if size is not None else self._raw.fetchmany()
        if not rows:
            return []
        if self._raw.description:
            columns = [col[0] for col in self._raw.description]
            return [TursoRow(columns, r) for r in rows]
        return rows

    def __iter__(self):
        for row in self.fetchall():
            yield row

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass


class LibsqlConnectionWrapper:
    """Wraps a raw libSQL connection with sqlite3-compatible API & Row wrappers."""

    def __init__(self, raw_conn):
        self._raw = raw_conn
        self._row_factory = None

    @property
    def row_factory(self):
        return self._row_factory

    @row_factory.setter
    def row_factory(self, val):
        self._row_factory = val

    def cursor(self):
        return LibsqlCursorWrapper(self._raw.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, seq_of_params):
        cur = self.cursor()
        cur.executemany(sql, seq_of_params)
        return cur

    def executescript(self, script_str):
        lines = [ln for ln in script_str.splitlines() if not ln.strip().startswith('--')]
        clean_sql = '\n'.join(lines)
        statements = [s.strip() for s in clean_sql.split(';') if s.strip()]
        for stmt in statements:
            try:
                self.execute(stmt)
            except Exception as e:
                print(f"[Executescript] Warning: {e}")
        self.commit()

    def commit(self):
        return self._raw.commit()

    def rollback(self):
        if hasattr(self._raw, 'rollback'):
            return self._raw.rollback()

    def close(self):
        try:
            return self._raw.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


def _connect_turso(database_url: str, auth_token: str):
    """Establishes and returns a wrapped Turso libSQL connection."""
    try:
        raw_conn = libsql.connect(database_url, auth_token=auth_token)
    except TypeError:
        raw_conn = libsql.connect(database=database_url, auth_token=auth_token)
    return LibsqlConnectionWrapper(raw_conn)


# ---------------------------------------------------------------------------
# Schema executor — works with both sqlite3 and libsql (Turso)
# ---------------------------------------------------------------------------

def _execute_schema(conn, schema_path: str):
    """Execute SQL schema file one statement at a time (compatible with Turso)."""
    with open(schema_path, 'r', encoding='utf-8') as f:
        raw_sql = f.read()
    lines = [ln for ln in raw_sql.splitlines() if not ln.strip().startswith('--')]
    clean_sql = '\n'.join(lines)
    statements = [s.strip() for s in clean_sql.split(';') if s.strip()]
    for stmt in statements:
        try:
            conn.execute(stmt)
        except Exception as e:
            print(f"[Schema] Warning: {e}")
    conn.commit()


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """Unified database interface for Turso (libsql) and local SQLite."""

    def __init__(self, turso_url: str = None, auth_token: str = None,
                 local_path: str = None):
        if local_path:
            self.local_path = local_path
            self.turso_url = None
            self.auth_token = None
            self._use_turso = False
        else:
            self.turso_url = turso_url or _config.TURSO_DB_URL
            self.auth_token = auth_token or _config.TURSO_AUTH_TOKEN
            self.local_path = None
            self._use_turso = bool(self.turso_url and self.auth_token and HAS_LIBSQL)

    def connect(self):
        if self._use_turso:
            return _connect_turso(self.turso_url, self.auth_token)
        else:
            path = self.local_path or DEFAULT_DB_PATH
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            return conn

    @property
    def is_turso(self) -> bool:
        return self._use_turso


# ---------------------------------------------------------------------------
# Master Database connection
# ---------------------------------------------------------------------------

def get_master_db_connection():
    """
    Returns a connection to the Master Database.
    Uses Turso (TURSO_DB_URL + TURSO_AUTH_TOKEN) if set, else local master.db.
    """
    turso_url = _config.TURSO_DB_URL
    turso_token = _config.TURSO_AUTH_TOKEN

    if turso_url and turso_token and HAS_LIBSQL:
        return _connect_turso(turso_url, turso_token)

    conn = sqlite3.connect(MASTER_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ---------------------------------------------------------------------------
# Plan configuration
# ---------------------------------------------------------------------------

DEFAULT_PLAN_CONFIG = {
    'free': {
        'max_products': 25,
        'features': {
            'custom_domain': False,
            'analytics': False,
            'export_csv': False,
            'discount_codes': False,
            'whatsapp_checkout': True,
            'pos_receipt': False
        }
    },
    'basic': {
        'max_products': 100,
        'features': {
            'custom_domain': False,
            'analytics': False,
            'export_csv': True,
            'discount_codes': True,
            'whatsapp_checkout': True,
            'pos_receipt': True
        }
    },
    'premium': {
        'max_products': 1000,
        'features': {
            'custom_domain': True,
            'analytics': True,
            'export_csv': True,
            'discount_codes': True,
            'whatsapp_checkout': True,
            'pos_receipt': True
        }
    }
}


def _tenant_get(tenant, key, default=None):
    """Safe column access for sqlite3.Row / libsql Row objects."""
    try:
        return tenant[key]
    except (IndexError, KeyError, TypeError):
        return default


def get_tenant_feature_flags(tenant) -> dict:
    if not tenant:
        return DEFAULT_PLAN_CONFIG['free']['features'].copy()

    plan = (_tenant_get(tenant, 'plan') or 'free')
    base_features = DEFAULT_PLAN_CONFIG.get(plan, DEFAULT_PLAN_CONFIG['free'])['features'].copy()

    raw_flags = _tenant_get(tenant, 'feature_flags')
    if raw_flags:
        try:
            overrides = json.loads(raw_flags) if isinstance(raw_flags, str) else raw_flags
            if isinstance(overrides, dict):
                base_features.update(overrides)
        except Exception:
            pass
    return base_features


# ---------------------------------------------------------------------------
# Master DB initialization
# ---------------------------------------------------------------------------

def init_master_db():
    """Initialize master database tables and seed defaults. Safe to call on every startup."""
    conn = get_master_db_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS master_admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        store_name TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        owner_email TEXT,
        owner_phone TEXT,
        custom_domain TEXT UNIQUE,
        turso_db_url TEXT,
        turso_auth_token TEXT,
        cloudinary_folder TEXT,
        plan TEXT DEFAULT 'free',
        theme TEXT DEFAULT 'standard',
        is_active INTEGER DEFAULT 1,
        max_products INTEGER DEFAULT 100,
        feature_flags TEXT DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    for migration_sql in [
        "ALTER TABLE tenants ADD COLUMN feature_flags TEXT DEFAULT '{}'",
        "ALTER TABLE tenants ADD COLUMN theme TEXT DEFAULT 'standard'",
        "ALTER TABLE tenants ADD COLUMN turso_db_url TEXT",
        "ALTER TABLE tenants ADD COLUMN turso_auth_token TEXT",
    ]:
        try:
            cur.execute(migration_sql)
        except Exception:
            pass

    cur.execute("SELECT COUNT(*) as cnt FROM master_admins")
    if cur.fetchone()['cnt'] == 0:
        default_pwd = os.environ.get('MASTER_ADMIN_PASSWORD', 'master123')
        default_user = os.environ.get('MASTER_ADMIN_USERNAME', 'master')
        pwd_hash = _hash_password(default_pwd)
        if not os.environ.get('MASTER_ADMIN_PASSWORD'):
            print('[Security] WARNING: MASTER_ADMIN_PASSWORD is not set - using an insecure default. Set it in Render.', flush=True)
        cur.execute(
            "INSERT INTO master_admins (username, password_hash) VALUES (?, ?)",
            [default_user, pwd_hash]
        )

    cur.execute("SELECT COUNT(*) as cnt FROM tenants")
    if cur.fetchone()['cnt'] == 0:
        cur.execute("""
        INSERT INTO tenants (slug, store_name, owner_name, owner_email, plan, is_active, max_products, feature_flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ['default', 'The Cozy Corner', 'Store Owner', 'owner@example.com',
              'free', 1, 100, json.dumps(DEFAULT_PLAN_CONFIG['free']['features'])])

    conn.commit()
    conn.close()
    clear_tenant_cache()


# ---------------------------------------------------------------------------
# Tenant DB helpers
# ---------------------------------------------------------------------------

# Small in-memory cache so every page view doesn't hit the master database several times.
# Entries expire after TENANT_CACHE_SECONDS (default 60) and are cleared whenever a store is
# created, edited, suspended or deleted from this server.
_TENANT_CACHE_TTL = int(os.environ.get('TENANT_CACHE_SECONDS', '60'))
_tenant_cache = {}


def clear_tenant_cache():
    """Forget cached store lookups (call after changing the tenants table)."""
    _tenant_cache.clear()


def get_tenant_by_identifier(identifier: str):
    """Looks up tenant by slug or custom_domain (cached for a short time)."""
    now = time.time()
    hit = _tenant_cache.get(identifier)
    if hit and (now - hit[0]) < _TENANT_CACHE_TTL:
        return hit[1]

    conn = get_master_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM tenants WHERE slug = ? OR custom_domain = ? LIMIT 1",
            [identifier, identifier]
        )
        tenant = cur.fetchone()
    finally:
        conn.close()
    _tenant_cache[identifier] = (now, tenant)
    return tenant


def _ensure_tenant_schema(conn, slug: str):
    """Auto-init tenant schema if the orders table is missing (e.g. wiped Turso DB)."""
    try:
        conn.execute("SELECT 1 FROM orders LIMIT 1")
    except Exception:
        print(f"[DB] Tenant '{slug}' schema missing — auto-initialising.", flush=True)
        base_dir = os.path.dirname(__file__)
        schema_path = os.path.join(base_dir, 'schema.sql')
        _execute_schema(conn, schema_path)
        # Run migrations too
        for migration in [
            "ALTER TABLE orders ADD COLUMN reserved_until TEXT",
            "ALTER TABLE customers ADD COLUMN post_office TEXT",
            "ALTER TABLE customers ADD COLUMN district TEXT",
            "ALTER TABLE customers ADD COLUMN landmark TEXT",
            "ALTER TABLE products ADD COLUMN image2 TEXT",
            "ALTER TABLE products ADD COLUMN size TEXT",
        ]:
            try:
                conn.execute(migration)
            except Exception:
                pass
        try:
            conn.commit()
        except Exception:
            pass


def get_tenant_db_connection(tenant_slug: str):
    """
    Returns a connection to the specific tenant's database.
    Priority:
      1. Tenant's own Turso DB (credentials stored in master DB)
      2. Default Turso DB (for 'default' tenant via TURSO_DB_URL env var)
      3. Local SQLite fallback (local dev only)
    """
    if not tenant_slug or tenant_slug == 'default':
        conn = Database().connect()
        _ensure_tenant_schema(conn, 'default')
        return conn

    try:
        row = get_tenant_by_identifier(tenant_slug)

        if row and row['turso_db_url'] and row['turso_auth_token'] and HAS_LIBSQL:
            conn = Database(
                turso_url=row['turso_db_url'],
                auth_token=row['turso_auth_token']
            ).connect()
            _ensure_tenant_schema(conn, tenant_slug)
            return conn
    except Exception as e:
        print(f"[DB] Could not fetch Turso credentials for '{tenant_slug}': {e}")

    if os.environ.get('FLASK_ENV') == 'production' and tenant_slug not in _warned_ephemeral:
        _warned_ephemeral.add(tenant_slug)
        print(f"[DB] WARNING: store '{tenant_slug}' has NO Turso database, so it is using a local "
              f"SQLite file that Render wipes on every deploy (products, images, orders will be lost). "
              f"Set TURSO_API_TOKEN + TURSO_ORG_NAME and use 'Move to permanent DB' in the master panel.",
              flush=True)

    tenant_db_path = os.path.join(TENANTS_DIR, f"{tenant_slug}.db")
    conn = Database(local_path=tenant_db_path).connect()
    _ensure_tenant_schema(conn, tenant_slug)
    return conn


_warned_ephemeral = set()


def tenant_has_permanent_db(tenant) -> bool:
    """True if the store (a tenants row) has its own Turso DB. The default store uses TURSO_DB_URL."""
    if _tenant_get(tenant, 'slug') == 'default':
        return bool(_config.TURSO_DB_URL and _config.TURSO_AUTH_TOKEN)
    return bool(_tenant_get(tenant, 'turso_db_url') and _tenant_get(tenant, 'turso_auth_token'))


def migrate_tenant_to_turso(slug: str):
    """
    Give a store that is running on a local (ephemeral) SQLite file its own Turso database.
    Copies any rows still in the local file; if the file was already wiped, seeds a fresh store
    with a temporary admin password. Returns (copied_rows, temp_password_or_None).
    """
    import secrets
    if slug == 'default':
        raise ValueError("The default store uses TURSO_DB_URL and does not need migration.")
    if not HAS_LIBSQL:
        raise RuntimeError("libsql is not installed on this server.")
    if not _turso_is_platform_configured():
        raise RuntimeError("Set TURSO_API_TOKEN and TURSO_ORG_NAME in Render first.")

    m_conn = get_master_db_connection()
    row = m_conn.execute("SELECT * FROM tenants WHERE slug = ?", [slug]).fetchone()
    if not row:
        m_conn.close()
        raise ValueError("Store not found.")
    if row['turso_db_url'] and row['turso_auth_token']:
        m_conn.close()
        raise ValueError("This store already has a permanent database.")
    store_name = row['store_name']

    url, token = _create_turso_tenant_db(slug)
    if not url:
        m_conn.close()
        raise RuntimeError("Could not create the Turso database (see Render logs for the Turso error).")

    t_conn = _connect_turso(url, token)
    _execute_schema(t_conn, os.path.join(os.path.dirname(__file__), 'schema.sql'))
    _ensure_tenant_schema(t_conn, slug)

    copied = 0
    local_path = os.path.join(TENANTS_DIR, f"{slug}.db")
    if os.path.exists(local_path):
        src = sqlite3.connect(local_path)
        src.row_factory = sqlite3.Row
        tables = [r['name'] for r in src.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for tbl in tables:
            try:
                rows = src.execute(f'SELECT * FROM "{tbl}"').fetchall()
                for r in rows:
                    cols = r.keys()
                    t_conn.execute(
                        f'INSERT OR REPLACE INTO "{tbl}" ({",".join(chr(34)+c+chr(34) for c in cols)}) '
                        f'VALUES ({",".join("?" * len(cols))})', list(r))
                    copied += 1
            except Exception as e:
                print(f"[Migrate] skipped table {tbl}: {e}", flush=True)
        src.close()

    temp_pw = None
    has_admin = t_conn.execute("SELECT 1 FROM settings WHERE key='admin_password'").fetchone()
    if not has_admin:
        temp_pw = secrets.token_urlsafe(8)
        t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('shop_name', ?)", [store_name])
        t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', 'admin')")
        t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)",
                       [_hash_password(temp_pw)])
    t_conn.commit()
    t_conn.close()

    m_conn.execute("UPDATE tenants SET turso_db_url = ?, turso_auth_token = ? WHERE slug = ?", [url, token, slug])
    m_conn.commit()
    m_conn.close()
    clear_tenant_cache()
    return copied, temp_pw


def update_tenant_admin_password(slug: str, new_password: str):
    """Updates the admin_password for a tenant in their settings table."""
    pwd_hash = _hash_password(new_password)
    t_conn = get_tenant_db_connection(slug)
    t_conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)",
        [pwd_hash]
    )
    t_conn.commit()
    t_conn.close()
    return True


def delete_tenant(tenant_id: int):
    """Deletes a tenant from master DB and removes their Turso DB or local SQLite file."""
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()
    cur.execute(
        "SELECT slug, store_name, turso_db_url FROM tenants WHERE id = ?",
        [tenant_id]
    )
    tenant = cur.fetchone()
    if not tenant:
        m_conn.close()
        raise ValueError("Store tenant not found.")

    slug = tenant['slug']
    store_name = tenant['store_name']
    if slug == 'default':
        m_conn.close()
        raise ValueError("The default primary store cannot be deleted.")

    cur.execute("DELETE FROM tenants WHERE id = ?", [tenant_id])
    m_conn.commit()
    clear_tenant_cache()
    m_conn.close()

    if tenant['turso_db_url']:
        _delete_turso_tenant_db(slug)

    db_path = os.path.join(TENANTS_DIR, f"{slug}.db")
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass

    return store_name


def provision_new_tenant(slug: str, store_name: str, owner_name: str,
                         owner_email: str = '', owner_phone: str = '',
                         plan: str = 'free', theme: str = 'standard',
                         max_products: int = 100, custom_domain: str = '',
                         admin_username: str = 'admin',
                         admin_password: str = 'admin123',
                         feature_flags: dict = None):
    """
    Provisions a new tenant:
      1. Creates a dedicated Turso database (if Turso Platform API is configured).
      2. Inserts tenant record in master DB with Turso credentials.
      3. Initializes schema and seeds settings in the new tenant DB.
    """
    slug = slug.strip().lower()
    master_conn = get_master_db_connection()
    m_cur = master_conn.cursor()

    m_cur.execute("SELECT id FROM tenants WHERE slug = ?", [slug])
    if m_cur.fetchone():
        master_conn.close()
        raise ValueError(f"Store identifier '{slug}' is already taken.")

    if custom_domain:
        m_cur.execute("SELECT id FROM tenants WHERE custom_domain = ?", [custom_domain])
        if m_cur.fetchone():
            master_conn.close()
            raise ValueError(f"Custom domain '{custom_domain}' is already assigned to another store.")

    resolved_features = DEFAULT_PLAN_CONFIG.get(plan, DEFAULT_PLAN_CONFIG['free'])['features'].copy()
    if feature_flags:
        resolved_features.update(feature_flags)
    flags_json = json.dumps(resolved_features)

    # Try to create a dedicated Turso database for this tenant
    tenant_turso_url, tenant_turso_token = _create_turso_tenant_db(slug)

    m_cur.execute("""
    INSERT INTO tenants (slug, store_name, owner_name, owner_email, owner_phone,
                         custom_domain, plan, theme, max_products, feature_flags,
                         turso_db_url, turso_auth_token)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [slug, store_name, owner_name, owner_email, owner_phone,
          custom_domain or None, plan, theme or 'standard', max_products, flags_json,
          tenant_turso_url, tenant_turso_token])
    master_conn.commit()
    clear_tenant_cache()
    master_conn.close()

    # Initialize tenant database (Turso or local SQLite)
    if tenant_turso_url and tenant_turso_token and HAS_LIBSQL:
        t_conn = _connect_turso(tenant_turso_url, tenant_turso_token)
    else:
        tenant_db_path = os.path.join(TENANTS_DIR, f"{slug}.db")
        t_conn = sqlite3.connect(tenant_db_path)
        t_conn.row_factory = sqlite3.Row

    base_dir = os.path.dirname(__file__)
    schema_path = os.path.join(base_dir, 'schema.sql')
    _execute_schema(t_conn, schema_path)

    user_to_set = (admin_username or 'admin').strip() or 'admin'
    pwd_hash = _hash_password(admin_password)
    t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('shop_name', ?)", [store_name])
    t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', ?)", [user_to_set])
    t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)", [pwd_hash])
    if owner_phone:
        t_conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('whatsapp_number', ?)", [owner_phone])

    for migration in [
        "ALTER TABLE orders ADD COLUMN reserved_until TEXT",
        "ALTER TABLE customers ADD COLUMN post_office TEXT",
        "ALTER TABLE customers ADD COLUMN district TEXT",
        "ALTER TABLE customers ADD COLUMN landmark TEXT",
    ]:
        try:
            t_conn.execute(migration)
        except Exception:
            pass

    t_conn.commit()
    t_conn.close()
    return True


# ---------------------------------------------------------------------------
# Default database convenience helpers
# ---------------------------------------------------------------------------

_default_db = Database()


def get_connection():
    """Get a connection from the default (main) database."""
    return _default_db.connect()


def is_turso() -> bool:
    """Check if the default DB is using Turso."""
    return _default_db.is_turso