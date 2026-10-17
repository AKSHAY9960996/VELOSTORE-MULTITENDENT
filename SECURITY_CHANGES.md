# Security fixes: what changed and what you must do on deploy

## Do this BEFORE / WHEN you deploy (Render)
1. **`SECRET_KEY`** must be set (your render.yaml already generates one). The app now refuses to start in production without it.
2. **`TOKEN_ENCRYPTION_KEY`** (new, in render.yaml, auto-generated). Existing store database tokens are encrypted automatically at first start. **Do not change or lose this key**, or the app can no longer open the store databases (if you ever do, re-create the stores' tokens). If you do not set it, `SECRET_KEY` is used instead, so then do not rotate `SECRET_KEY` either.
3. **`MASTER_ADMIN_PASSWORD`** must be set. If no master admin exists yet and this is missing, none is created (no more `master123` default).
4. Optional: **`DEFAULT_STORE_ADMIN_PASSWORD`**, the password for the "default" store when its database is first created.
5. **If your live default store or master login still uses `admin123` / `master123`, change it now.** The app prints a warning at startup if it finds either.
6. Everyone is logged out once after deploying (the session format changed).
7. The service worker version was bumped (`admin-shell-v3`). Installed admin PWAs will drop their old cached admin pages automatically.

## Your 15 issues
| # | Status | What was done |
|---|--------|---------------|
| 3 CSRF | Fixed | `csrf.py`: per-session token + Origin/Referer check on every POST. All 17 forms carry `{{ csrf_field() }}`. The checkout `fetch` sends it through its FormData. |
| 4 /diag | Fixed | Master admin only, otherwise 404. URL prefix removed from output. |
| 5 Redirect | Fixed | `/s/<shop>/admin/...` only redirects to a plain path that matches a real admin route. (Note: it could not leave your domain, but it was sloppy and could produce odd URLs.) |
| 6 Rate limit | Fixed | `ratelimit.py`: stored in the master DB, so it survives restarts and works across workers. |
| 7 Cookies | Fixed | HttpOnly, SameSite=Lax, Secure (production only), 8-hour lifetime. |
| 8 Headers | Fixed | X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS (production/HTTPS), and a CSP (scripts are now locked down with a per-request nonce, see "Added in this round"). `X-XSS-Protection` was left out on purpose (deprecated). |
| 9 SECRET_KEY | Fixed | Required in production; stable dev key locally. |
| 10 Seed password | Fixed | No password in `schema.sql`; always a salted hash. The `admin123` fallbacks in the login code and the master "new store" form are gone too. |
| 11 Race condition | Fixed | `UPDATE ... WHERE stock >= ?` inside one transaction, and the whole checkout rolls back if any item fails. Tested: 8 parallel buyers for 3 items gives exactly 3 orders. |
| 12 Master login | Fixed | Same DB-backed lockout. |
| 13 active_tenant_slug | Fixed | Redundant session write removed. |
| 14 Quantity cap | Fixed | Max 50 per item (`MAX_QTY_PER_ITEM`), max 50 cart lines. |
| 15 Password length | Fixed | Minimum 8, rejects common/simple passwords and a password equal to the username. |
| 16 Upload size | Fixed | 16 MB limit with a friendly error page. |
| 17 Plain-text fallback | Logged | Kept for migration; every legacy-format login is now logged and upgraded to a hash. |

## Extra bugs I found and fixed
* **Negative quantity at checkout** (critical): `quantity = -5` passed the stock check, *increased* stock and made the order total negative.
* **Duplicate cart lines** for one product bypassed the stock check.
* **Login lockout could be dodged** by sending a fake `X-Forwarded-For` header. Now uses `ProxyFix` (one trusted hop).
* **Double stock restore**: expiry cleanup and admin status changes could restore the same stock twice. Status changes are now atomic, and re-activating an order checks stock.
* **Order status** accepted any text. Now whitelisted.
* **CSV formula injection** in exports (customer names like `=HYPERLINK(...)`).
* **Store identifier** was used unchecked in a file path (`../` in a slug). Now strict + reserved words blocked.
* **Product form** crashed (500) on bad numbers and accepted negative price/stock.
* **Master "Login As"** changed state on a GET link. Now POST.
* **Service worker** cached authenticated admin pages (stale CSRF tokens, data left on shared devices). No longer cached; admin pages send `Cache-Control: no-store`.
* **Changing the admin password** now needs the current password, and the confirmation message used to be erased by `session.clear()`.
* **Order confirmation** stored the whole WhatsApp message in the cookie (could exceed 4 KB and silently break the session). Now rebuilt from the database.
* Checkout validates phone, 6-digit pincode and field lengths.

## Added in this round
* **Store database tokens are now encrypted at rest** (Fernet/AES, key from `TOKEN_ENCRYPTION_KEY`). Old plain-text tokens are upgraded automatically. A wrong key fails loudly instead of silently showing an empty local database.
* **"Clear data" buttons now ask for the admin password** (server-side, rate-limited), so a left-open session cannot wipe a shop.
* **Scripts are now locked down by the CSP (no `'unsafe-inline'` in `script-src`).** Every inline `<script>` carries a random per-request nonce, and all ~50 inline `onclick`/`onchange`/`onsubmit`/`oninput`/`onfocus`/`onmouseover` attributes were replaced (including the ones `cart.js` builds in JavaScript strings) by `data-on-*` attributes handled by `static/js/ui-events.js`. A script an attacker manages to inject into a page will no longer run. `script-src-attr 'none'` is set as well. `style-src` still allows inline styles (see below).
* **Fixed a real injection bug found along the way:** product names were pasted into JavaScript strings inside `onclick="..."` (delete button, sales-history cards). A product named `');...//` could run code in the admin's browser. Arguments now travel as JSON in data attributes and can never become code.
* **Admin usernames now live in the master `tenants` table** (`admin_username`) with a case-insensitive UNIQUE index. The "is this username taken?" check is one indexed query instead of opening every store's database, and the database itself now refuses duplicates, so two people creating or renaming stores at the same moment cannot both get the same name. Existing stores are filled in automatically at startup (a store whose database cannot be reached yet is still protected by a fallback check). Behaviour change: a *suspended* store now keeps its username reserved. If two old stores already shared a username, the older one keeps it, the newer one is reported in the log and needs a new username in Master > Edit store.
* Tests: 97 unit checks (`python tests/test_security.py`) plus 60 real-browser checks (`python tests/test_browser_csp.py`, needs `pip install -r requirements-dev.txt && playwright install chromium`). The browser test clicks through the storefront, admin and master pages in Chromium and fails on any CSP violation or JS error, and also proves injected inline script/handlers are blocked.

## Still recommended (not done; bigger or needs your decision)
* **Remove `'unsafe-inline'` from `style-src`** (the last inline allowance in the CSP). Needs the many `style="..."` attributes moved into CSS classes. Much lower risk than scripts, so it is optional.
* **Pin exact dependency versions** (`pip freeze`) and add `pip-audit` to your routine.
* **Back up the master DB regularly** (see BACKUP_RESTORE.md) and add a "type the shop name to confirm" step to the *Clear data* buttons.
* Email/WhatsApp alert for new orders and for failed-login lockouts.
* Per-store logout is still a GET link (low risk with SameSite=Lax).

## Tests
`python tests/test_security.py` runs 97 checks (CSRF, lockouts, redirects, checkout abuse, race condition, tenant isolation...). It uses a temporary database.
