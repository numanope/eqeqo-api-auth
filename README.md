# EQEQO Auth API

Centralized authentication and authorization service for the **Eqeqo** ecosystem.
Handles token issuance, validation, and access control for all other APIs.


## ⚙️ Setup

**Local setup**
```bash
psql -U postgres -f db/run_all.sql
cp .env.example .env
cargo run
```

**Tests**
Tests assume the seeded `auth_api` database from `db/run_all.sql`.
Server default: `http://127.0.0.1:7878`

```bash
cargo test
```

Environment:
```
DATABASE_URL=postgres://USER:PASSWORD@HOST/auth_api
SERVER_PORT=7878
TOKEN_TTL_SECONDS=300
TOKEN_RENEW_THRESHOLD_SECONDS=30
```


## 🧩 Endpoints

| Method | Path | Description (minimal example) |
| ------ | ---- | ----------------------------- |
| **POST** | `/auth/login` | Issue token per user+service. Example: `{"username":"adm1","password":"adm1-hash","service_id":"Service A"}` |
| **POST** | `/auth/logout` | Revoke current token. Header: `token: <value>` |
| **GET** | `/auth/profile` | Validate and optionally renew token. Header: `token: <value>` |
| **POST** | `/check-token` | Validate token (optional `service_id` / `user_id` in body to enforce match). Header: `token: <value>` |
| **GET** | `/users` | List users. Header: `token: <value>` |
| **POST** | `/users` | Create user. Example body: `{"username":"user1","password_hash":"pass","name":"User","person_type":"N","document_type":"DNI","document_number":"123"}` + header `token`. |
| **PUT** | `/users/{id}` | Update user. Example: `{"name":"New Name"}` + header `token`. |
| **DELETE** | `/users/{id}` | Delete user and revoke tokens. Header: `token`. |
| **GET** | `/roles` | List roles. Header: `token`. |
| **POST** | `/roles` | Create role. Example: `{"name":"Editor"}` + header `token`. |
| **GET** | `/roles/{id}` | Get role. Header: `token`. |
| **PUT** | `/roles/{id}` | Update role. Example: `{"name":"New Role"}` + header `token`. |
| **DELETE** | `/roles/{id}` | Delete role. Header: `token`. |
| **GET** | `/permissions` | List permissions. Header: `token`. |
| **POST** | `/permissions` | Create permission. Example: `{"name":"export"}` + header `token`. |
| **PUT** | `/permissions/{id}` | Update permission. Example: `{"name":"export_csv"}` + header `token`. |
| **DELETE** | `/permissions/{id}` | Delete permission. Header: `token`. |
| **POST** | `/role-permissions` | Assign permission to role. Example: `{"role_id":1,"permission_id":2}` + header `token`. |
| **DELETE** | `/role-permissions` | Remove permission from role. Example: `{"role_id":1,"permission_id":2}` + header `token`. |
| **GET** | `/roles/{id}/permissions` | List role permissions. Header: `token`. |
| **POST** | `/services` | Create service. Example: `{"name":"Stock","description":"Inventory"}` + header `token`. |
| **GET** | `/services` | List services. Header: `token`. |
| **PUT** | `/services/{id}` | Update service. Example: `{"description":"New desc"}` + header `token`. |
| **DELETE** | `/services/{id}` | Delete service. Header: `token`. |
| **POST** | `/service-roles` | Assign role to service. Example: `{"service_id":1,"role_id":2}` + header `token`. |
| **DELETE** | `/service-roles` | Remove role from service. Example: `{"service_id":1,"role_id":2}` + header `token`. |
| **GET** | `/services/{id}/roles` | List roles of a service. Header: `token`. |
| **POST** | `/person-service-roles` | Assign role to person in service. Example: `{"person_id":1,"service_id":1,"role_id":2}` + header `token`. |
| **DELETE** | `/person-service-roles` | Remove role from person in service. Example: `{"person_id":1,"service_id":1,"role_id":2}` + header `token`. |
| **GET** | `/people/{person_id}/services/{service_id}/roles` | List roles of person in service. Header: `token`. |
| **GET** | `/services/{service_id}/roles/{role_id}/people` | List people with role in service. Header: `token`. |
| **GET** | `/people/{person_id}/services` | List services of a person. Header: `token`. |
| **GET** | `/check-permission` | Check permission for a person in a service. Example body: `{"person_id":1,"service_id":1,"permission_name":"read"}` + header `token`. |
| **POST** | `/person-service-permissions` | Grant a permission directly to a person in a service (creates/uses a scoped role). Example: `{"person_id":1,"service_id":1,"permission_name":"read"}` + header `token`. |


## 🔁 Token logic
- Generated at login (`hash(secret + random + timestamp)`). NO JWT nor similar.
- Stored centrally in `auth.tokens_cache` with `payload` and `modified_at`.
- Tokens are issued per **user + service**; login requests must include the target service id or name. Tokens cannot be reused across services.
- All protected requests must include `token:` header (no query params). `/auth/login` is the only public route.
- Short TTL (2–5 min) with atomic renewal near expiry to avoid contention.
- Revocation on logout or user deletion; cleanup job periodically removes expired tokens.
- `/check-token` can optionally validate both user and service to avoid cross-service leaks.
- No tokens in URLs.
- Minimal logging per request: token, endpoint, timestamp, IP.
- Background cleanup job trims expired tokens every ~60 seconds.


## 🧭 Use case diagram

```mermaid
sequenceDiagram
  autonumber
  actor UI as Frontend (UI)
  participant BACK as Backend (Stock / Sales / Manufacturing)
  participant AUTH as Auth API

  %% 1. Login
  UI->>AUTH: POST /auth/login { user, pass }
  AUTH-->>UI: { token }

  %% 2. Request from UI to Back
  UI->>BACK: GET /{service_id_string}/{user_id_string}\nheaders: token

  %% 3. Cache check + request to Out
  alt Valid local cache (<= 1 min)
    BACK-->>UI: responds using cached payload
  else Expired or missing cache, valid token in Out
    BACK->>AUTH: POST /check-token\n{ token, service_id, user_id }
    AUTH-->>BACK: { valid: true, payload }
    BACK-->>UI: responds and saves payload in cache (1 min)
  else Expired or missing cache, invalid token in Out
    BACK->>AUTH: POST /check-token\n{ token, service_id, user_id }
    AUTH-->>BACK: { valid: false }
    BACK-->>UI: 401 Unauthorized
  end

  %% 4. Writes always validated
  Note over BACK,AUTH: Write operations (POST / PATCH / DELETE)\nalways query Out without using local cache.

  %% 5. Logout
  UI->>AUTH: POST /auth/logout { token }
  AUTH-->>UI: 200 Logged out
```


MIT © Eqeqo
