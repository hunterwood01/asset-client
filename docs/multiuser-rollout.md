# Asset Client multi-user rollout

## Scope of this change

This pull request adds the first backend foundation: a Node.js API, PostgreSQL-backed sessions, local username/password authentication, and administrator-only user management endpoints. The existing browser-only inventory UI is not yet wired to these endpoints; that is intentionally a separate migration step.

## Roles

- `admin`: may list, create, edit, disable and change roles/passwords for users.
- `operator`: may authenticate and use the authenticated API surface, but receives HTTP 403 from user-administration endpoints.

All protected endpoints enforce authorization on the server. Hiding a UI element is not an authorization control.

## Security

- Passwords are hashed with Argon2id; plaintext passwords are never stored in the database.
- Sessions are stored in PostgreSQL, use an HTTP-only cookie, SameSite=Strict and an eight-hour rolling expiry.
- Login attempts are rate limited.
- The API accepts JSON for write requests and can restrict the request Origin with `APP_ORIGIN`.
- PostgreSQL is on the private Compose network and has no published host port.
- Use HTTPS at the VM's public reverse proxy. Set `APP_ORIGIN` to the exact HTTPS origin before exposing the application.
- Generate unique secrets and never commit the real `.env` file.

The bootstrap administrator is created only when both bootstrap environment variables are set and the username does not already exist. Changing the bootstrap password later does not change an existing account; use the admin API to rotate it.

## Local/VM setup

1. Copy `.env.example` to `.env` and set strong random values for the database password and session secret.
2. Set a unique bootstrap administrator password (minimum 12 characters).
3. Set `APP_ORIGIN` to the exact URL users will open. Terminate TLS at the VM reverse proxy.
4. Run `docker compose up -d --build`.
5. Verify `GET /api/health` through the web origin and sign in with the bootstrap admin.
6. After confirming the administrator exists, remove `BOOTSTRAP_ADMIN_PASSWORD` from the runtime environment and recreate the API container.
7. Back up the PostgreSQL volume and test restoring it before relying on this system.

## API

- `GET /api/health`: database connectivity health check.
- `POST /api/auth/login`: JSON `{ "username": "...", "password": "..." }`.
- `GET /api/auth/me`: current session user.
- `POST /api/auth/logout`: destroy current session.
- `GET /api/admin/users`: admin only.
- `POST /api/admin/users`: admin only; JSON `{ "username": "...", "password": "...", "role": "operator" }`.
- `PATCH /api/admin/users/:id`: admin only; accepts `active`, `role`, and/or `password`.

## Not yet delivered

This does not yet migrate inventory data from browser localStorage to PostgreSQL, enforce login in the existing UI, or provide a user-management screen. Do not expose this as a completed multi-user portal until the follow-up PRs are merged, tested and deployed.
