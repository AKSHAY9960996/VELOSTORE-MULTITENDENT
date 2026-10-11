"""
VeloStore entry point.  Run with:  gunicorn app:app

The code is split into:
  core.py              Flask app, tenant middleware, database/upload/auth helpers, error pages
  routes_storefront.py customer-facing pages (home, product, checkout, /s/<store>)
  routes_admin.py      store-owner dashboard
  routes_master.py     platform (master) admin
  db.py / security.py  database access and password hashing
Importing the route modules below registers their URLs on the shared Flask app.
"""
from core import app  # noqa: F401  (gunicorn looks for `app` here)
import routes_storefront  # noqa: F401
import routes_admin  # noqa: F401
import routes_master  # noqa: F401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
