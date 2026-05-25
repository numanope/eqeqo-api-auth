# Demo Database Snapshot

Pre-seeded data loaded by `db/run_all.sql` (IDs are deterministic because the DB is recreated each time).

`db/run_all.sql` also loads `db/authorization_seed.sql` after the demo data. That file seeds the minimal production-oriented authorization catalog without changing database structure.

To add or refresh only the POS/API authorization catalog in an existing database, run `db/authorization_seed.sql` directly. It is idempotent: it uses `ON CONFLICT` and does not drop, delete, or recreate existing data.

## Services (`auth.services`)
| id | name       | description                  |
| -- | ---------- | ---------------------------- |
| 1  | Service A  | Demo catalog service         |
| 2  | Service B  | Internal billing service     |
| 3  | Service C  | Customer support portal      |
| 4  | UI Store   | Frontend store surface       |
| 5  | ui-store   | Frontend store surface       |
Service name is used as the client/app identifier.

## Roles (`auth.role`)
| id | name   |
| -- | ------ |
| 1  | Admin  |
| 2  | User   |
| 3  | Editor |
| 4  | Viewer |

## Permissions (`auth.permission`)
| id | name   |
| -- | ------ |
| 1  | read   |
| 2  | write  |
| 3  | update |
| 4  | delete |
| 5  | share  |

The authorization seed adds user-facing permissions with minimal names such as:

- `sales.read`, `sales.create`, `sales.cancel`, `sales.refund`
- `cash.read`, `cash.open`, `cash.close`, `cash.move`
- `products.read`, `products.create`, `products.update`, `products.delete`
- `stock.read`, `stock.move`, `stock.adjust`
- `purchases.read`, `purchases.create`, `purchases.update`, `purchases.cancel`
- `contacts.read`, `contacts.create`, `contacts.update`, `contacts.delete`
- `reports.read`, `reports.export`
- `users.read`, `users.invite`, `users.update`, `users.delete`
- `roles.read`, `roles.update`
- `settings.read`, `settings.update`
- `tax.read`, `tax.send`, `tax.cancel`
- `payments.read`, `payments.create`, `payments.refund`

## POS/API roles from `authorization_seed.sql`

The user-facing roles are:

- `Owner`
- `Manager`
- `Cashier`
- `Stock`
- `Purchase`
- `Accounting`
- `Auditor`
- `Support`

These roles are linked to the known services/apps: `pos`, `api-auth`, `api-sales`, `api-stocks`, and `api-commercial`.

Full POS role-to-permission matrix: `db/POS_ROLE_PERMISSION_MATRIX.md`.

## POS test users

`authorization_seed.sql` creates these users if they do not exist and assigns them to the first active demo business it can find; in a fresh `db/run_all.sql` database this is business `1`. Each user is assigned to `pos` and to every backend API where the same role is enabled, so POS-facing calls can pass through `api-sales`, `api-stocks`, and `api-commercial`.
They all use password `<username>-hash`.
Use `POST /check-permission` with body `{"business_id":1,"service_id":"pos"}` in a fresh DB to read their effective POS role and permissions.

| username | password      | POS role   | Intended test profile |
| -------- | ------------- | ---------- | --------------------- |
| adm2     | adm2-hash     | Owner      | Full POS/admin access |
| adm3     | adm3-hash     | Manager    | Daily operations without destructive user/role control |
| usr4     | usr4-hash     | Cashier    | Sales, quotes, own cash actions and customer creation |
| editor2  | editor2-hash  | Stock      | Product and inventory operations |
| editor3  | editor3-hash  | Purchase   | Provider and purchase operations |
| usr5     | usr5-hash     | Accounting | Money, tax, reports and refunds |
| viewer2  | viewer2-hash  | Auditor    | Read-only audit plus exports |
| viewer3  | viewer3-hash  | Support    | Diagnosis/read access without money operations |

## People (`auth.person`)
| id | username | name        | doc        |
| -- | -------- | ----------- | ---------- |
| 1  | adm1     | Admin One   | DNI 00000001 |
| 2  | usr1     | User One    | DNI 00000002 |
| 3  | usr2     | User Two    | DNI 00000003 |
| 4  | usr3     | User Three  | DNI 00000004 |
| 5  | editor1  | Editor One  | DNI 00000005 |
| 6  | viewer1  | Viewer One  | DNI 00000006 |
| 7  | juan     | Juan Demo   | DNI 00000007 |
| 8  | adm2     | Admin Two   | DNI 00000008 |
| 9  | adm3     | Admin Three | DNI 00000009 |
| 10 | usr4     | User Four   | DNI 00000010 |
| 11 | usr5     | User Five   | DNI 00000011 |
| 12 | editor2  | Editor Two  | DNI 00000012 |
| 13 | editor3  | Editor Three | DNI 00000013 |
| 14 | viewer2  | Viewer Two  | DNI 00000014 |
| 15 | viewer3  | Viewer Three | DNI 00000015 |
Passwords: stored as bcrypt hashes; for demo users the plaintext is `<username>-hash` (e.g., adm1-hash).
`auth.person.can_register_services` is `FALSE` by default; demo user `adm1` has it set to `TRUE`.

## Businesses (`auth.businesses`)
| id | name          | doc         |
| -- | ------------- | ----------- |
| 1  | Demo Business | RUC 00000000001 |

All seeded user-role assignments are scoped to this default business.

## Business users (`auth.business_users`)
Each seeded person with a service role is linked to business `1`.

## Service ↔ Role links (`auth.service_roles`)
| service_id | role_id | meaning                 |
| ---------- | ------- | ----------------------- |
| 1          | 1       | Service A has Admin     |
| 1          | 2       | Service A has User      |
| 2          | 2       | Service B has User      |
| 3          | 3       | Service C has Editor    |
| 4          | 4       | UI Store has Viewer     |
| 4          | 1       | UI Store has Admin      |
| 4          | 2       | UI Store has User       |
| 4          | 3       | UI Store has Editor     |
| 5          | 4       | ui-store has Viewer     |

## Role ↔ Permission links (`auth.role_permission`)
| role_id | permission_id | note                    |
| ------- | ------------- | ----------------------- |
| 1       | 1             | Admin → read            |
| 1       | 2             | Admin → write           |
| 1       | 3             | Admin → update          |
| 1       | 4             | Admin → delete          |
| 2       | 1             | User  → read            |
| 2       | 2             | User  → write           |
| 2       | 3             | User  → update          |
| 2       | 4             | User  → delete          |
| 3       | 1             | Editor → read           |
| 3       | 3             | Editor → update         |
| 4       | 1             | Viewer → read           |

## Business ↔ Person ↔ Service ↔ Role links (`auth.person_service_role`)
| business_id | person_id | service_id | role_id | note                         |
| ----------- | --------- | ---------- | ------- | ---------------------------- |
| 1           | 1         | 1          | 1       | adm1 is Admin in Service A   |
| 1           | 2         | 1          | 2       | usr1 is User in Service A    |
| 1           | 3         | 2          | 2       | usr2 is User in Service B    |
| 1           | 4         | 3          | 3       | usr3 is Editor in Service C  |
| 1           | 5         | 1          | 1       | editor1 is Admin in Service A |
| 1           | 5         | 3          | 3       | editor1 is Editor in Service C |
| 1           | 6         | 5          | 4       | viewer1 is Viewer in ui-store |
| 1           | 7         | 4          | 4       | juan is Viewer in UI Store   |
| 1           | 8         | 4          | 1       | adm2 is Admin in UI Store    |
| 1           | 9         | 4          | 1       | adm3 is Admin in UI Store    |
| 1           | 10        | 4          | 2       | usr4 is User in UI Store     |
| 1           | 11        | 4          | 2       | usr5 is User in UI Store     |
| 1           | 12        | 4          | 3       | editor2 is Editor in UI Store |
| 1           | 13        | 4          | 3       | editor3 is Editor in UI Store |
| 1           | 14        | 4          | 4       | viewer2 is Viewer in UI Store |
| 1           | 15        | 4          | 4       | viewer3 is Viewer in UI Store |

Use these IDs for quick manual requests (e.g., `GET /people/7/services/4` with `token` from user `juan`). Refresh by running `psql -U postgres -f db/run_all.sql`.

## Cache tables
`auth.tokens_cache`: stores plaintext token, `payload`, and `expires_at` with `created_at` and `updated_at`. Service tokens do not expire and rely on manual revocation.

`auth.permissions_cache`: stores `permissions` by `(token, business_id, service_id)` with `expires_at`, `created_at`, and `updated_at`.
