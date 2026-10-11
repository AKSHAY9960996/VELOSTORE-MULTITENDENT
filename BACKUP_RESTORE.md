# VeloStore: Where data lives, backups and restore

## Where everything is stored

| Data | Lives in | Survives a Render deploy? |
|---|---|---|
| Stores, products, orders, customers, settings | **Turso** (one database per store, plus the master database) | Yes |
| Product photos and logos | **Cloudinary** | Yes |
| Anything saved on Render's disk (`static/uploads`, `*.db` files) | Render's temporary disk | **No. Wiped on every deploy and restart** |

The app now refuses to save images on Render's disk in production. If Cloudinary is not set up, the upload fails with a clear message instead of silently losing the image.

## Check that old products do not use local images

Images uploaded while Cloudinary was failing may be stored as a bare file name (not a link starting with `https://`). They will not survive a deploy.

```bash
turso db shell velostore-master "SELECT slug, turso_db_url FROM tenants;"
turso db shell <store-database-name> "SELECT id, name, image, image2 FROM products WHERE (image IS NOT NULL AND image NOT LIKE 'http%') OR (image2 IS NOT NULL AND image2 NOT LIKE 'http%');"
```
If any rows appear, open that product in the store admin and upload the photo again.

## Back up (do this weekly, it takes a minute)

Turso's free plan keeps only the **last 24 hours** of history for restore, so keep your own copy too.

```bash
turso auth login
turso db list
turso db shell velostore-master .dump > backup-master-2026-10-11.sql
turso db shell vs-<store-slug> .dump > backup-<store-slug>-2026-10-11.sql
```
Store the `.sql` files somewhere safe (Google Drive, email to yourself). Do not commit them to GitHub because they contain customer data.

## Test a restore once (so you know it works)

Turso restores by creating a **new** database from a point in time. It never overwrites the original.

1. Pick a time within the last 24 hours, in UTC:
   ```bash
   turso db create velostore-restore-test --from-db velostore-master --timestamp 2026-10-11T10:00:00Z
   ```
2. Check the data is there:
   ```bash
   turso db shell velostore-restore-test "SELECT slug, store_name FROM tenants;"
   ```
3. Delete the test copy:
   ```bash
   turso db destroy velostore-restore-test
   ```

The restored copy may be missing up to about 15 seconds of the most recent changes before the time you pick.

## If you ever need to recover for real

1. Create the restored database (as above, with a new name such as `velostore-master-restored`).
2. Create a token for it: `turso db tokens create velostore-master-restored`
3. Get its URL: `turso db show velostore-master-restored --url`
4. In Render, change `TURSO_DB_URL` and `TURSO_AUTH_TOKEN` to the new values and redeploy.
5. For a single store's database, update that store's `turso_db_url` and `turso_auth_token` in the master database's `tenants` table instead.
6. When you are sure everything works, delete the old broken database.

## Restore from a `.sql` backup file

```bash
turso db create velostore-master-recovered --from-dump backup-master-2026-10-11.sql
```
Then follow steps 2 to 5 above.

## Clean up the Git repository (one time)

Local database files and sample images should not be in GitHub. This removes them from the repository only. Your local copies stay on your computer.

```bash
git rm --cached --ignore-unmatch database.db master.db
git rm -r --cached --ignore-unmatch tenants_db static/uploads __pycache__
git add -f static/uploads/.gitkeep
git add .gitignore
git commit -m "Stop tracking databases, uploads and cache files"
git push
```

If your GitHub repository is **public**, treat any password stored in those old database files as exposed. Change the master password and each store admin password after this update.
