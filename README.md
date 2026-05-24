# EQEQO API AUTH

Centralized authentication and authorization service for the **Eqeqo** ecosystem.
Issues short-lived tokens, renews them atomically near expiry, and enforces access control with a DB-backed token cache plus periodic cleanup.


## ⚙️ Setup


**Environment:**

Copy and modify.

```
cp ./.env-example ./.env
```


**Database + user setup**
- Set `AUTH_DATABASE_URL` in `.env` (used by `db/run_all.sql` to grant schema access).
- Run the script as the `postgres` superuser; it creates/recreates the `api_auth` DB and applies grants.

Example `AUTH_DATABASE_URL`:
```
AUTH_DATABASE_URL=postgres://USER:PASSWORD@localhost/api_auth
```


**Local setup**
```bash
cp .env.example .env
set -a; . ./.env; set +a
sudo --preserve-env=AUTH_DATABASE_URL -u postgres psql -f db/run_all.sql
cargo run
```

**Production service**
See [deploy/PRODUCTION.md](deploy/PRODUCTION.md) and [deploy/api-auth.service](deploy/api-auth.service) for a permanent `systemd` setup.


**Tests**

Integration tests rely on the seeded `api_auth` DB from `db/run_all.sql`.
Default server: `http://127.0.0.1:7878`

```bash
cargo test
```

Data reference: see `./db/DB.md` (seeded dataset: IDs, users, services, roles, permissions).

## 🔐 Auth essentials
- All protected routes require the `user-token:` header (never pass tokens in URLs).
- Tokens are cached centrally in `auth.tokens_cache`; renewals write once per request and only when near expiry.
- Login returns the existing token when still valid; otherwise issues a new one.
- Logout or user deletion revokes related tokens; a background job prunes expired tokens every ~60 seconds.
- Minimal logging per request records token, endpoint, timestamp, and IP.
- Tokens are stored in plaintext in the cache; user passwords are stored as bcrypt hashes (demo users seeded with bcrypt).
- `/check-permission` uses headers for tokens: `user-token` always, plus `service-token` for backend calls; body must carry `business_id` and only carries `service_id` when no service token is used.

## 🔎 Auth flows (simple)
**Frontend or unsafe clients**
- Client sends only the `user-token` header.
- Client calls `GET /me` after login to obtain allowed businesses and optional app settings in one request.
- Client stores the selected `business_id` in session/UI state.
- Backend maps public context to internal `service_id`.
- Backend calls `POST /check-permission` with `user-token` header and body `{ business_id, service_id }`.
- Auth treats requests with `service_id` as frontend/unsafe context.
- Do not expose a service token or `service_id` to end users.

**Backend to backend**
- Use `user-token` + `service-token` headers.
- Call `POST /check-permission` with those headers and body `{ business_id }`.
- Auth treats requests with `service_token` as backend-to-backend.
- Service token stays only on the server.

## 🧭 POS business selection flow
1. Login in `pos` with `POST /auth/login`.
2. Call `GET /me` with `user-token`; if a business is already active, also send `business-id` and `app-id: pos`.
3. If `businesses` is empty, block access with a message like "No tienes negocios asignados".
4. If `businesses` has one item, select it automatically.
5. If `businesses` has many items, show a selector and store the chosen `business_id`.
6. Send the selected `business_id` in every permission check and business API request.

Example response:

```json
{
  "payload": { "user_id": 1, "username": "adm1", "name": "Admin One" },
  "businesses": [
    {
      "id": 1,
      "name": "Demo Business",
      "legal_name": "Demo Business",
      "document_type": "RUC",
      "document_number": "00000000001",
      "status": true
    }
  ],
  "active_business": {
    "id": 1,
    "name": "Demo Business",
    "legal_name": "Demo Business",
    "document_type": "RUC",
    "document_number": "00000000001",
    "status": true
  },
  "settings": {}
}
```

## 🚀 Quick request example
Example: fetching user data for “Juan” (id `7`) from client `servcli1` using a user token:

```bash
curl -X GET "http://127.0.0.1:7878/users/7" \
  -H "user-token: user_tok_example_123" \
  -H "x-client-id: servcli1"
```

`x-client-id` is optional metadata; the API currently only enforces the `user-token` header.

Example: checking permission (frontend/unsafe):
```bash
curl -X POST "http://127.0.0.1:7878/check-permission" \
  -H "user-token: user_tok_example_123" \
  -H "content-type: application/json" \
  -d '{"business_id":1,"service_id":2}'
```

Example: checking permission (backend/safe):
```bash
curl -X POST "http://127.0.0.1:7878/check-permission" \
  -H "user-token: user_tok_example_123" \
  -H "service-token: svc_tok_example_456" \
  -H "content-type: application/json" \
  -d '{"business_id":1}'
```


## 🧩 Endpoints

| Method | Path | Description (minimal example) |
| ------ | ---- | ----------------------------- |
| **POST** | `/auth/login` | Issue token for user (global). Example: `{"username":"adm1","password":"adm1-hash"}`. |
| **POST** | `/auth/register` | Public user registration. Example: `{"username":"user1","password_hash":"pass","name":"User","person_type":"N","document_type":"DNI","document_number":"123"}` |
| **POST** | `/auth/logout` | Revoke current token. Header: `user-token: <value>` |
| **GET** | `/auth/profile` | Validate session and optionally renew token. Header: `user-token: <value>`. Returns only token payload, renewal state, and expiration. |
| **GET** | `/me` | UI startup context. Header: `user-token`; optional `business-id` + `app-id`. Returns user payload, businesses, active business, and settings when applicable. |
| **PATCH** | `/me/settings` | Merge current user's settings. Header: `user-token`. Example: `{"business_id":1,"app_id":"pos","settings_patch":{"theme":"dark"}}`. |
| **POST** | `/check-permission` | Validate access. Headers: `user-token` and optional `service-token`. Body requires `business_id`: `{ "business_id": 1, "service_id": 2 }` without service token; `{ "business_id": 1 }` with service token. |
| **GET** | `/me/businesses` | List active businesses assigned to current user. Header: `user-token`. Compatibility/specific listing endpoint; POS startup should prefer `GET /me`. |
| **POST** | `/me/businesses` | Create a business for current user. Header: `user-token`. Example: `{"name":"Haití","legal_name":"Haití SAC","document_type":"RUC","document_number":"..."}`. Optional `service_id`; default is `UI Store`. User becomes `Admin` for that business/service. |
| **GET** | `/businesses` | List businesses. Header: `user-token`. Requires `can_register_services`. |
| **POST** | `/businesses` | Create business. Example: `{"name":"Haití","legal_name":"Haití SAC","document_type":"RUC","document_number":"..."}` + header `user-token`. Requires `can_register_services`. |
| **PUT** | `/businesses/{id}` | Update business. Same body as create, plus optional `"status": true`. Requires `can_register_services` or `Admin` role in that business. |
| **DELETE** | `/businesses/{id}` | Soft-delete business. Header: `user-token`. Requires `can_register_services`. |
| **GET** | `/businesses/{id}/users` | List users assigned to a business. Header: `user-token`. Requires `can_register_services`. |
| **POST** | `/business-users` | Assign user to business. Example: `{"business_id":1,"person_id":1}` + header `user-token`. Requires `can_register_services`. |
| **DELETE** | `/business-users` | Remove user from business. Example: `{"business_id":1,"person_id":1}` + header `user-token`. Requires `can_register_services`. |
| **POST** | `/business-invitations` | Business admin creates invite. Example: `{"business_id":1,"service_id":49,"role_id":2}` + header `user-token`. |
| **POST** | `/business-invitations/accept` | Logged user accepts invite. Example: `{"code":"abc123"}` + header `user-token`. |
| **GET** | `/users` | List users. Header: `user-token: <value>` |
| **POST** | `/users` | Admin creates user. Same body as `/auth/register` + header `user-token`. |
| **PUT** | `/users/{id}` | Update user. Example: `{"name":"New Name"}` + header `user-token`. |
| **DELETE** | `/users/{id}` | Delete user and revoke tokens. Header: `user-token`. |
| **GET** | `/roles` | List roles. Header: `user-token`. |
| **POST** | `/roles` | Create role. Example: `{"name":"Editor"}` + header `user-token`. |
| **GET** | `/roles/{id}` | Get role. Header: `user-token`. |
| **PUT** | `/roles/{id}` | Update role. Example: `{"name":"New Role"}` + header `user-token`. |
| **DELETE** | `/roles/{id}` | Delete role. Header: `user-token`. |
| **GET** | `/permissions` | List permissions. Header: `user-token`. |
| **POST** | `/permissions` | Create permission. Example: `{"name":"export"}` + header `user-token`. |
| **PUT** | `/permissions/{id}` | Update permission. Example: `{"name":"export_csv"}` + header `user-token`. |
| **DELETE** | `/permissions/{id}` | Delete permission. Header: `user-token`. |
| **POST** | `/role-permissions` | Assign permission to role. Example: `{"role_id":1,"permission_id":2}` + header `user-token`. |
| **DELETE** | `/role-permissions` | Remove permission from role. Example: `{"role_id":1,"permission_id":2}` + header `user-token`. |
| **GET** | `/roles/{id}/permissions` | List role permissions. Header: `user-token`. |
| **POST** | `/services` | Create service. Example: `{"name":"Stock","description":"Inventory"}` + header `user-token`. Requires `can_register_services`. |
| **GET** | `/services` | List services. Header: `user-token`. |
| **PUT** | `/services/{id}` | Update service. Example: `{"description":"New desc"}` + header `user-token`. Requires `can_register_services`. |
| **DELETE** | `/services/{id}` | Delete service. Header: `user-token`. Requires `can_register_services`. |
| **POST** | `/services/{id}/token` | Issue service token. Header: `user-token`. Requires `can_register_services`. |
| **POST** | `/service-roles` | Assign role to service. Example: `{"service_id":1,"role_id":2}` + header `user-token`. |
| **DELETE** | `/service-roles` | Remove role from service. Example: `{"service_id":1,"role_id":2}` + header `user-token`. |
| **GET** | `/services/{id}/roles` | List roles of a service. Header: `user-token`. |
| **POST** | `/person-service-roles` | Assign role to person in business + service. Example: `{"business_id":1,"person_id":1,"service_id":1,"role_id":2}` + header `user-token`. |
| **DELETE** | `/person-service-roles` | Remove role from person in business + service. Example: `{"business_id":1,"person_id":1,"service_id":1,"role_id":2}` + header `user-token`. |
| **GET** | `/people/{person_id}/services/{service_id}/roles` | List roles of person in service. Header: `user-token`. |
| **GET** | `/services/{service_id}/roles/{role_id}/people` | List people with role in service. Header: `user-token`. |
| **GET** | `/people/{person_id}/services` | List services of a person. Header: `user-token`. |
| **GET** | `/people/{person_id}/services/{service_id}` | Get user data plus roles/permissions for that service. Header: `user-token`. |
| **POST** | `/person-service-permissions` | Grant a permission directly to a person in a business + service (creates/uses a scoped role). Example: `{"business_id":1,"person_id":1,"service_id":1,"permission_name":"read"}` + header `user-token`. |


## 🔁 Token logic
- Generated at login (`hash(secret + random + timestamp)`). NO JWT nor similar.
- Stored centrally in `auth.tokens_cache` with `payload` and `expires_at`; token values are stored in plaintext.
- Per-business, per-service permission snapshots are stored in `auth.permissions_cache` keyed by `(token, business_id, service_id)` with `permissions` and `expires_at`.
- Tokens are issued per **user** (global); services query permissions via `POST /check-permission`.
- Each user has a single active token; login reuses it until it expires.
- All protected requests must include `user-token:` header (no query params). Public routes are `/auth/login` and `/auth/register`.
- Settings context uses headers `business-id` and `app-id` on `GET /me`.
- Short TTL (2–5 min) with atomic renewal near expiry to avoid contention.
- `/check-permission` reads from cache and only rewrites on renew threshold (no multiple writes per request).
- Revocation on logout or user deletion; cleanup job periodically removes expired tokens.
- Access checks are always `POST /check-permission` with `user-token` header and either body `{ business_id, service_id }` or `service-token` header plus body `{ business_id }`; missing `business_id` returns `missing_business_id`.
- No tokens in URLs.
- Minimal logging per request: token, endpoint, timestamp, IP.
- Background cleanup job trims expired tokens every ~60 seconds.

## 🏢 Business permission model
- Businesses live in `auth.businesses`.
- User membership lives in `auth.business_users` as `(business_id, person_id)`.
- User roles live in `auth.person_service_role` as `(business_id, person_id, service_id, role_id)`.
- Invite codes live in `auth.business_invitations`; accepting one creates `business_users` and `person_service_role`.
- `POST /me/businesses` creates a business for the current user and assigns `Admin`; it returns the new `business_id`.
- `PUT /businesses/{id}` can be used by a global admin or by an `Admin` of that same business; POS uses this to edit business profile data.
- The seeded demo business is id `1` in fresh demo databases.
- New clients should never invent the ID; they must read it from `GET /me` response field `businesses`.

## User app settings
Settings live in `auth.user_app_settings`, one JSONB row per `(business_id, user_id, app_id)`. POS should store small UI settings there by calling `PATCH /me/settings`; the server shallow-merges `settings_patch` into the current JSON and never stores one giant JSON for all businesses.

## POS startup contract
After login, POS should call only `GET /me` with `user-token`. If it already has an active business, also send `business-id: <id>` and `app-id: pos`; then use `businesses`, `active_business`, and `settings` from that single response instead of calling `/auth/profile` plus `/me/businesses`.

## Business invite flow
Leader clicks "invite user" → `POST /business-invitations` returns `code` → new user registers/login → enters code → `POST /business-invitations/accept` → user now appears in `GET /me/businesses`.

## Business creation flow
User registers/login → user creates business with `POST /me/businesses` → response returns `business_id` → `GET /me` lists every active business linked to the user → POS stores active `business_id`.


## 🧭 Use case diagram

```mermaid
sequenceDiagram
  autonumber
  actor UI as Frontend (UI)
  participant BACK as Backend (Stock / Sales / Manufacturing)
  participant AUTH as Auth API

  %% 1. Login
  UI->>AUTH: POST /auth/login { user, pass }
  AUTH-->>UI: { user_token }

  %% 2. Request from UI to Back
  UI->>BACK: GET /resource\nheaders: user-token
  Note over BACK: Maps public context to internal business_id + service_id

  %% 3. Cache check + request to Out
  alt Valid local cache (<= 1 min)
    BACK-->>UI: responds using backend cache
  else Expired or missing cache, valid token in Out
    BACK->>AUTH: POST /check-permission\nheaders: user-token\nbody: { business_id, service_id }
    AUTH-->>BACK: { valid: true, payload }
    BACK-->>UI: responds and saves payload in backend cache (1 min)
  else Expired or missing cache, invalid token in Out
    BACK->>AUTH: POST /check-permission\nheaders: user-token\nbody: { business_id, service_id }
    AUTH-->>BACK: { valid: false }
    BACK-->>UI: 401 Unauthorized
  end

  %% 4. Writes always validated
  Note over BACK,AUTH: Write operations (POST / PATCH / DELETE)\nalways query Out without using local cache.

  %% 5. Logout
  UI->>AUTH: POST /auth/logout\nheaders: user-token
  AUTH-->>UI: 200 Logged out
```

SUIGUIENTE IMPLEMENTACION, OMITIR POR AHORA
## 🧰 Rust client (server-side)
Location: `crates/eqeqo-api-auth-client`

- Covers all endpoints in this API.
- Includes an in-memory permission cache (default TTL 60s).
- You can plug a DB-backed cache by implementing `PermissionCache`.

Example:
```rust
use eqeqo_api_auth_client::{ApiAuthClient, ServiceContext};
use serde_json::json;

let client = ApiAuthClient::new("http://127.0.0.1:7878");
let login = client.auth_login("adm1", "adm1-hash").await?;
let user_token = login["user_token"].as_str().unwrap();

let access = client
  .check_permission(user_token, ServiceContext::service_id(2))
  .await?;

let created = client
  .create_service(user_token, json!({ "name": "Stock", "description": "Inventory" }))
  .await?;
```


MIT © Eqeqo

// this line is a test
