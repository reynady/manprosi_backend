# Migration from MySQL to SQLite

I have successfully migrated the backend from MySQL to SQLite (using `better-sqlite3`).

## Changes Made

1.  **Dependencies**: Replaced `mysql2` with `better-sqlite3`.
2.  **Database Configuration**:
    *   Created `db.js` which handles the SQLite connection.
    *   The database file is located at `manprosi-backend/data/app.db`.
    *   `initDB` and `initTables` are implemented to automatically create tables and seed initial data (Admin user, roles) if they don't exist.
3.  **Code Refactoring**:
    *   Refactored `server.js` to use synchronous SQLite queries (`db.prepare().run/all`).
    *   Refactored `modules/recommendations/repo.js` to use SQLite syntax.
    *   Updated `modules/recommendations/index.js` to remove strict `information_schema` dependency.
4.  **Environment Variables**: The app no longer depends on `DB_HOST`, `DB_USER`, `DB_PASSWORD`.

## How to Run

1.  Make sure you are in the `manprosi-backend` directory.
2.  Install dependencies (if you haven't yet, though I ran it):
    ```bash
    npm install
    ```
3.  Start the server:
    ```bash
    npm run dev
    # or
    node server.js
    ```
4.  The server will create `data/app.db` automatically on the first run.

## Credentials

*   **Admin User**: `admin` / `admin123` (Automatically seeded)

## Deployment Note

*   **Railway**: This setup works perfectly on Railway. Ensure you attach a volume to `/data` if you want the database to persist across redeploys.
*   **Vercel**: Vercel is serverless and generally read-only for the filesystem. Using a local SQLite file (`app.db`) on Vercel directly is **not recommended** for a writable application as data will be lost on new deployments or function restarts. For Vercel, consider using a DB-as-a-service (like Turso or Neon) or sticking to Railway/VPS for file-based SQLite.
