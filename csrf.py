"""
Small, dependency-free CSRF protection for every state-changing request.

How it works
  * Each browser session gets a random token (stored in the signed session cookie).
  * Every POST/PUT/PATCH/DELETE must send that token, either as the form field
    ``csrf_token`` or in the ``X-CSRFToken`` header.
  * If the browser sends an Origin (or Referer) header it must match this site.

Templates use  {{ csrf_token() }}  or  {{ csrf_field() }}  (a ready-made hidden input).
"""
import hmac
import secrets
from urllib.parse import urlparse

from flask import abort, jsonify, request, session
from markupsafe import Markup, escape

_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
_SESSION_KEY = '_csrf_token'


class CSRFError(Exception):
    pass


def generate_csrf_token() -> str:
    token = session.get(_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_SESSION_KEY] = token
    return token


def csrf_field() -> Markup:
    return Markup('<input type="hidden" name="csrf_token" value="%s">') % generate_csrf_token()


def _same_origin(url: str) -> bool:
    try:
        return urlparse(url).netloc.lower() == request.host.lower()
    except Exception:
        return False


def _validate():
    # 1. Origin / Referer check (modern browsers always send one on cross-site POSTs)
    origin = request.headers.get('Origin')
    if origin and origin != 'null':
        if not _same_origin(origin):
            raise CSRFError('Origin does not match')
    elif origin == 'null':
        raise CSRFError('Opaque origin')
    elif request.headers.get('Referer') and not _same_origin(request.headers['Referer']):
        raise CSRFError('Referer does not match')

    # 2. Token check
    sent = request.form.get('csrf_token') or request.headers.get('X-CSRFToken') or ''
    expected = session.get(_SESSION_KEY, '')
    if not expected or not sent or not hmac.compare_digest(sent.encode(), expected.encode()):
        raise CSRFError('Missing or invalid CSRF token')


def init_csrf(app, error_renderer=None):
    """Register CSRF protection on the Flask app. Must be called before other before_request hooks."""
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.jinja_env.globals['csrf_field'] = csrf_field

    @app.before_request
    def _csrf_protect():
        if request.method in _SAFE_METHODS:
            return None
        try:
            _validate()
        except CSRFError as e:
            print(f"[CSRF] blocked {request.method} {request.path}: {e}", flush=True)
            if request.path.startswith('/api/') or request.path.endswith('/checkout'):
                return jsonify(success=False, error='Your session expired. Please refresh the page and try again.'), 400
            if error_renderer:
                return error_renderer(400, 'Session expired',
                                      'For your security this request was blocked. '
                                      'Please go back, refresh the page and try again.')
            abort(400)
        return None
