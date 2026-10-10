import os
import sqlite3
import hashlib

# Try to import libsql; fall back to sqlite3 for local dev
try:
    import libsql_experimental as libsql
    HAS_LIBSQL = True
except ImportError:
    HAS_LIBSQL = False

from config import get_config

_config = get_config()

TENANTS_DIR = os.path.join(os.path.dirname(__file__), 'tenants_db')
os.makedirs(TENANTS_DIR, exist_ok=True)


class Database:
    """
    Unified database interface for both Turso (libsql) and local SQLite.
    Supports specific tenant database connections.
    """

    def __init__(self, turso_url: str = None, auth_token: str = None,
                 local_path: str = None):
        self.turso_url = turso_url or _config.TURSO_DB_URL
        self.auth_token = auth_token or _config.TURSO_AUTH_TOKEN
        self.local_path = local_path
        self._use_turso = bool(self.turso_url and self.auth_token and HAS_LIBSQL)

    def connect(self):
        """
        Create and return a database connection.
        Returns a connection with row_factory set for dict-like access.
        """
        if self._use_turso:
            conn = libsql.connect(
                database=self.turso_url,
                auth_token=self.auth_token,
            )
            conn.row_factory = _turso_row_factory
        else:
            # Local SQLite fallback
            path = self.local_path or os.path.join(
                os.path.dirname(__file__), 'database.db'
            )
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")

        return conn

    @property
    def is_turso(self) -> bool:
        return self._use_turso


def _turso_row_factory(cursor, row):
    """
    Row factory for libsql that returns dict-like Row objects,
    compatible with sqlite3.Row interface (supports both row['key'] and row[index]).
    """
    columns = [description[0] for description in cursor.description]
    return TursoRow(columns, row)


class TursoRow:
    """
    A dict-like row wrapper for Turso results that mimics sqlite3.Row.
    Supports: row['column'], row[0], dict(row), 'column' in row, row.keys()
    """

    def __init__(self, columns, values):
        self._columns = columns
        self._values = values
        self._data = dict(zip(columns, values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def keys(self):
        return self._columns

    def values(self):
        return self._values

    def items(self):
        return self._data.items()

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __repr__(self):
        return f"TursoRow({self._data})"

    def __iter__(self):
        return iter(self._columns)

    def __len__(self):
        return len(self._columns)


# ---------------------------------------------------------------------------
# Master Database & Multi-Tenant Helper Functions
# ---------------------------------------------------------------------------

def get_master_db_connection():
    """
    Returns connection to the Master Database (`master.db` or Turso Master URL).
    """
    master_path = os.path.join(os.path.dirname(__file__), 'master.db')
    conn = sqlite3.connect(master_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


import json

# Predefined Plan Configurations (limits & default feature flags)
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


def get_tenant_feature_flags(tenant) -> dict:
    """
    Returns resolved feature flags dictionary for a tenant based on their plan and explicit overrides.
    """
    if not tenant:
        return DEFAULT_PLAN_CONFIG['free']['features'].copy()

    plan = (tenant['plan'] if 'plan' in tenant.keys() else 'free') or 'free'
    base_features = DEFAULT_PLAN_CONFIG.get(plan, DEFAULT_PLAN_CONFIG['free'])['features'].copy()

    raw_flags = tenant['feature_flags'] if 'feature_flags' in tenant.keys() else None
    if raw_flags:
        try:
            overrides = json.loads(raw_flags) if isinstance(raw_flags, str) else raw_flags
            if isinstance(overrides, dict):
                base_features.update(overrides)
        except Exception:
            pass
    return base_features


def init_master_db():
    """
    Initialize master database tables (`master_admins`, `tenants`) and seed default admin/tenant.
    """
    conn = get_master_db_connection()
    cur = conn.cursor()

    # Create master_admins table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS master_admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create tenants table
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

    # Migration: add feature_flags column if table already exists without it
    try:
        cur.execute("ALTER TABLE tenants ADD COLUMN feature_flags TEXT DEFAULT '{}'")
    except Exception:
        pass

    # Migration: add theme column if table already exists without it
    try:
        cur.execute("ALTER TABLE tenants ADD COLUMN theme TEXT DEFAULT 'standard'")
    except Exception:
        pass

    # Seed default master admin if empty
    cur.execute("SELECT COUNT(*) as cnt FROM master_admins")
    if cur.fetchone()['cnt'] == 0:
        default_pwd = os.environ.get('MASTER_ADMIN_PASSWORD', 'master123')
        default_user = os.environ.get('MASTER_ADMIN_USERNAME', 'master')
        pwd_hash = hashlib.sha256(default_pwd.encode('utf-8')).hexdigest()
        cur.execute(
            "INSERT INTO master_admins (username, password_hash) VALUES (?, ?)",
            [default_user, pwd_hash]
        )

    # Seed default primary tenant if empty
    cur.execute("SELECT COUNT(*) as cnt FROM tenants")
    if cur.fetchone()['cnt'] == 0:
        cur.execute("""
        INSERT INTO tenants (slug, store_name, owner_name, owner_email, plan, is_active, max_products, feature_flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ['default', 'The Cozy Corner', 'Store Owner', 'owner@example.com', 'free', 1, 100, json.dumps(DEFAULT_PLAN_CONFIG['free']['features'])])

    conn.commit()
    conn.close()


def get_tenant_by_identifier(identifier: str):
    """
    Looks up tenant by slug or custom_domain.
    """
    conn = get_master_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM tenants WHERE slug = ? OR custom_domain = ? LIMIT 1",
        [identifier, identifier]
    )
    tenant = cur.fetchone()
    conn.close()
    return tenant


def get_tenant_db_connection(tenant_slug: str):
    """
    Returns a connection to the specific tenant's database.
    If tenant is 'default', uses root database.db or configured Turso URL.
    Otherwise uses `tenants_db/<slug>.db`.
    """
    if not tenant_slug or tenant_slug == 'default':
        return Database().connect()

    tenant_db_path = os.path.join(TENANTS_DIR, f"{tenant_slug}.db")
    return Database(local_path=tenant_db_path).connect()


def update_tenant_admin_password(slug: str, new_password: str):
    """
    Updates the admin_password for a tenant in their database's settings table.
    """
    pwd_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
    t_conn = get_tenant_db_connection(slug)
    t_conn.execute("UPDATE settings SET value = ? WHERE key = 'admin_password'", [pwd_hash])
    t_conn.commit()
    t_conn.close()
    return True


def delete_tenant(tenant_id: int):
    """
    Deletes a tenant by ID from master.db and removes their local sqlite db file (safeguarding 'default').
    """
    m_conn = get_master_db_connection()
    cur = m_conn.cursor()
    cur.execute("SELECT slug, store_name FROM tenants WHERE id = ?", [tenant_id])
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
    m_conn.close()

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
    Provisions a brand new tenant database and inserts record into master.db.
    """
    slug = slug.strip().lower()
    master_conn = get_master_db_connection()
    m_cur = master_conn.cursor()

    # Check if slug or domain exists
    m_cur.execute("SELECT id FROM tenants WHERE slug = ?", [slug])
    if m_cur.fetchone():
        master_conn.close()
        raise ValueError(f"Store identifier '{slug}' is already taken.")

    if custom_domain:
        m_cur.execute("SELECT id FROM tenants WHERE custom_domain = ?", [custom_domain])
        if m_cur.fetchone():
            master_conn.close()
            raise ValueError(f"Custom domain '{custom_domain}' is already assigned to another store.")

    # Prepare feature flags JSON
    resolved_features = DEFAULT_PLAN_CONFIG.get(plan, DEFAULT_PLAN_CONFIG['free'])['features'].copy()
    if feature_flags:
        resolved_features.update(feature_flags)
    flags_json = json.dumps(resolved_features)

    # Create tenant entry in master db
    m_cur.execute("""
    INSERT INTO tenants (slug, store_name, owner_name, owner_email, owner_phone, custom_domain, plan, theme, max_products, feature_flags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [slug, store_name, owner_name, owner_email, owner_phone, custom_domain or None, plan, theme or 'standard', max_products, flags_json])
    master_conn.commit()
    master_conn.close()

    # Create tenant SQLite DB & execute schema.sql
    tenant_db_path = os.path.join(TENANTS_DIR, f"{slug}.db")
    t_conn = sqlite3.connect(tenant_db_path)
    t_conn.row_factory = sqlite3.Row

    base_dir = os.path.dirname(__file__)
    schema_path = os.path.join(base_dir, 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        t_conn.executescript(f.read())

    # Customize settings table for new tenant
    user_to_set = (admin_username or 'admin').strip() or 'admin'
    pwd_hash = hashlib.sha256(admin_password.encode('utf-8')).hexdigest()
    t_conn.execute("UPDATE settings SET value = ? WHERE key = 'shop_name'", [store_name])
    t_conn.execute("UPDATE settings SET value = ? WHERE key = 'admin_username'", [user_to_set])
    t_conn.execute("UPDATE settings SET value = ? WHERE key = 'admin_password'", [pwd_hash])
    if owner_phone:
        t_conn.execute("UPDATE settings SET value = ? WHERE key = 'whatsapp_number'", [owner_phone])

    # Run migrations if any
    try:
        t_conn.execute("ALTER TABLE orders ADD COLUMN reserved_until TEXT")
    except Exception:
        pass
    try:
        t_conn.execute("ALTER TABLE customers ADD COLUMN post_office TEXT")
    except Exception:
        pass

    t_conn.commit()
    t_conn.close()
    return True


# Default convenience
_default_db = Database()


def get_connection():
    """Get a connection from default database."""
    return _default_db.connect()


def is_turso() -> bool:
    """Check if default DB is Turso."""
    return _default_db.is_turso

