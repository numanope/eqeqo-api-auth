# AGENTS.md — Eqeqo Auth API

**Objective:**
Central service for authentication, authorization, and token management across Eqeqo APIs.

---

## 🔧 Tasks for agents
1. **Add table**
   - Add `auth.tokens_cache` with `token`, `payload`, `modified_at` (see README).
2. **Generate all success and fail tests in the currents api_test.rs file.**
   - Use the current structure, fixing server creation error and updating test cases on the list. dont change test technique.
/* OMIT FOR NOW
3.**Implement endpoints**
   - `/auth/login`: create token, insert record.
   - `/auth/logout`: delete token from table.
   - `/auth/profile`: validate token, renew conditionally.
   - `/check-token`: same validation logic for external APIs.
4. **Add token renewal logic**
   - Atomic SQL: `UPDATE ... RETURNING` + fallback `SELECT`.
   - Respect `TOKEN_TTL_SECONDS` and `TOKEN_RENEW_THRESHOLD_SECONDS`.
5. **Require header `token:` in all protected routes.**
6. **On user delete**, remove related tokens.
7. **Add minimal logging**
   - Record token, endpoint, timestamp, IP.
8. **Add cleanup job**
   - Periodically remove expired tokens.
*/
---

## 🧭 Flow summary
1. User logs in → Auth API generates token + payload.
2. Token stored in DB.
3. Other APIs send token to `/check-token`.
4. Auth API validates + renews timestamp.
5. If expired → 401.
6. Logout or user delete → remove token.

---

**Done criteria:**
- Token-based auth fully functional.
- Centralized cache in DB.
- Renewal atomic, short TTL.
- No token leaks via URL.
- Minimal overhead, max security.

---

MIT © Eqeqo

## Rol
Central identity and authorization API for the Eqeqo ecosystem.
Manages users, services, roles, and permissions.
Issues and validates access tokens for all other APIs.

---

## Project Structure
```
src/
├── main.rs           # Entry point
├── lib.rs            # Router setup
├── handlers/         # Domain-specific endpoints
│   ├── users.rs
│   ├── roles.rs
│   ├── permissions.rs
│   ├── services.rs
│   └── relations.rs
├── db.rs             # Database pool (SQLx)
├── auth.rs           # Token logic (JWT/HMAC)
├── models/           # Structs and DTOs
└── utils.rs          # Common helpers
db/
└── run_all.sql       # DB bootstrap and schema
```

---

## Development & Workflow

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

---

## Coding & Commit Rules
- Use **two-space indentation**, no tabs.
- Keep route handlers small and grouped by resource.
- Use `serde::Serialize` for DTOs.
- Use imperative commit prefixes: `feat:`, `fix:`, `refactor:`, `docs:`.
- Include SQL or curl samples in PRs that change endpoints.

---

## Environment Variables
- `DATABASE_URL` → PostgreSQL connection string
- `SERVER_PORT` → Port where service runs
- `JWT_SECRET` → Token signing secret
- `TOKEN_EXPIRY` → Default token lifetime

---

## Security Checklist
- Never commit `.env` or credentials.
- Validate tokens in all routes except `/auth/login`.
- Verify expired or revoked tokens are blocked.
- Restrict DB roles to least privilege.
- Expose only the JWT public key for other services.

---

## Integration Notes
- Every Eqeqo API must check user access through `/check-permission`.
- Bridges or frontends may verify JWT locally when possible.
- `Auth-API` logs all login and role assignment actions.

---

## Testing Guidelines
- Integration tests in `tests/api_tests.rs`.
- Tests require a seeded `auth_api` DB from `db/run_all.sql`.
- Use names like `login_behaves_as_expected` for consistency.

---

## Future Improvements
- Add refresh tokens.
- Add audit logs for permission changes.
- Implement service-to-service authentication (internal API keys).
