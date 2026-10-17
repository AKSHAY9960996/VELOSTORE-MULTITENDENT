"""
Login rate limiting stored in the master database.

Unlike an in-memory dict this survives restarts/deploys and is shared by every gunicorn worker.
Each "key" (e.g. "admin:myshop:1.2.3.4") gets MAX_ATTEMPTS failures inside WINDOW seconds
before it is locked for LOCKOUT seconds.
"""
from datetime import datetime, timedelta

from db import get_master_db_connection

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 5 * 60

_FMT = '%Y-%m-%d %H:%M:%S'


def ensure_table(conn=None):
    own = conn is None
    conn = conn or get_master_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            first_attempt TEXT NOT NULL,
            locked_until TEXT
        )
    """)
    conn.commit()
    if own:
        conn.close()


def _now():
    return datetime.utcnow()


def seconds_locked(*keys) -> int:
    """Seconds remaining on the longest active lockout among keys (0 = not locked). Fails open on DB errors."""
    try:
        conn = get_master_db_connection()
        try:
            remaining = 0
            for key in keys:
                row = conn.execute("SELECT locked_until FROM login_attempts WHERE key = ?", [key]).fetchone()
                if row and row['locked_until']:
                    until = datetime.strptime(row['locked_until'], _FMT)
                    remaining = max(remaining, int((until - _now()).total_seconds()))
            return max(0, remaining)
        finally:
            conn.close()
    except Exception as e:
        print(f"[RateLimit] check failed: {e}", flush=True)
        return 0


def record_failure(key, max_attempts=MAX_ATTEMPTS, lockout=LOCKOUT_SECONDS) -> int:
    """Count one failed login. Returns attempts remaining before lockout (0 = now locked)."""
    try:
        conn = get_master_db_connection()
        try:
            now = _now()
            row = conn.execute("SELECT attempts, first_attempt FROM login_attempts WHERE key = ?", [key]).fetchone()
            if row and (now - datetime.strptime(row['first_attempt'], _FMT)).total_seconds() < WINDOW_SECONDS:
                attempts = row['attempts'] + 1
                first = row['first_attempt']
            else:
                attempts, first = 1, now.strftime(_FMT)
            locked_until = (now + timedelta(seconds=lockout)).strftime(_FMT) if attempts >= max_attempts else None
            conn.execute(
                "INSERT OR REPLACE INTO login_attempts (key, attempts, first_attempt, locked_until) VALUES (?,?,?,?)",
                [key, attempts, first, locked_until])
            conn.commit()
            return max(0, max_attempts - attempts)
        finally:
            conn.close()
    except Exception as e:
        print(f"[RateLimit] record failed: {e}", flush=True)
        return max_attempts


def clear(*keys):
    try:
        conn = get_master_db_connection()
        try:
            for key in keys:
                conn.execute("DELETE FROM login_attempts WHERE key = ?", [key])
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[RateLimit] clear failed: {e}", flush=True)
