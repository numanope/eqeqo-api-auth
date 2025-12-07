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
```bash
cargo test
```
Tests assume the seeded `auth_api` database from `db/run_all.sql`.

Server default: `http://127.0.0.1:7878`

Environment:
```
DATABASE_URL=postgres://USER:PASSWORD@HOST/auth_api
SERVER_PORT=7878
TOKEN_TTL_SECONDS=300
TOKEN_RENEW_THRESHOLD_SECONDS=30
```


## 🧩 Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| **POST** | `/auth/login` | Generate a new token for valid user |
| **POST** | `/auth/logout` | Revoke token (delete from cache) — requires `token:` header |
| **GET** | `/auth/profile` | Validate token and return user payload (renews if valid) — requires `token:` header |
| **POST** | `/check-token` | Validate token from another API (atomic renewal logic) — requires `token:` header |
| **GET** | `/users` | List users |
| **POST** | `/users` | Create new user — requires `token:` header |
| **PUT** | `/users/{id}` | Update user — requires `token:` header |
| **DELETE** | `/users/{id}` | Disable or delete user — requires `token:` header |
| **GET** | `/roles` | List roles |
| **POST** | `/roles` | Create role — requires `token:` header |
| **GET** | `/permissions` | List permissions |
| **POST** | `/permissions` | Create permission — requires `token:` header |
| **POST** | `/role-permissions` | Assign permission to role — requires `token:` header |
| **POST** | `/service-roles` | Assign role to service — requires `token:` header |
| **POST** | `/person-service-roles` | Assign role to person in a service — requires `token:` header |


## 🔁 Token logic
- Generated at login (`hash(secret + random + timestamp)`). NO JWT nor similar.
- Stored centrally in `auth.tokens_cache` with `payload` and `modified_at`.
- All protected requests must include `token:` header (no query params). `/auth/login` is the only public route.
- Short TTL (2–5 min) with atomic renewal near expiry to avoid contention.
- Revocation on logout or user deletion; cleanup job periodically removes expired tokens.
- No tokens in URLs.
- Minimal logging per request: token, endpoint, timestamp, IP.


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
