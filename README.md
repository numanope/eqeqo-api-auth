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
| **POST** | `/auth/logout` | Revoke token (delete from cache) |
| **GET** | `/auth/profile` | Validate token and return user payload (renews if valid) |
| **POST** | `/check-token` | Validate token from another API (atomic renewal logic) |
| **GET** | `/users` | List users |
| **POST** | `/users` | Create new user |
| **PUT** | `/users/{id}` | Update user |
| **DELETE** | `/users/{id}` | Disable or delete user |
| **GET** | `/roles` | List roles |
| **POST** | `/roles` | Create role |
| **GET** | `/permissions` | List permissions |
| **POST** | `/permissions` | Create permission |
| **POST** | `/role-permissions` | Assign permission to role |
| **POST** | `/service-roles` | Assign role to service |
| **POST** | `/person-service-roles` | Assign role to person in a service |


## 🔁 Token logic
- Generated at login (`hash(secret + random + timestamp)`). NO JWT nor similar.
- Stored in `auth.tokens_cache` with `payload` and `modified_at`.
- Renewed automatically if not expired.
- Removed on logout or user deletion.
All requests must include token in *header*

```
token: <token>
```
- No tokens in URLs.
- Tokens stored centrally in DB.
- Short TTL (2–5 min). Cache life, must be defined in one single place in code.
- Conditional atomic renewal to prevent DB contention.
- Revocation: delete from table.
- Logs: minimal (token, endpoint, ts, ip).


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
