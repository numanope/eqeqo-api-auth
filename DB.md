# Demo Database Snapshot

Pre-seeded data loaded by `db/run_all.sql` (IDs are deterministic because the DB is recreated each time).

## Services (`auth.services`)
| id | name       | description                  |
| -- | ---------- | ---------------------------- |
| 1  | Service A  | Demo catalog service         |
| 2  | Service B  | Internal billing service     |
| 3  | Service C  | Customer support portal      |
| 4  | UI Store   | Frontend store surface       |

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

## Service ↔ Role links (`auth.service_roles`)
| service_id | role_id | meaning                 |
| ---------- | ------- | ----------------------- |
| 1          | 1       | Service A has Admin     |
| 1          | 2       | Service A has User      |
| 2          | 2       | Service B has User      |
| 3          | 3       | Service C has Editor    |
| 4          | 4       | UI Store has Viewer     |

## Role ↔ Permission links (`auth.role_permission`)
| role_id | permission_id | note                    |
| ------- | ------------- | ----------------------- |
| 1       | 1             | Admin → read            |
| 1       | 2             | Admin → write           |
| 1       | 3             | Admin → update          |
| 1       | 4             | Admin → delete          |
| 2       | 1             | User  → read            |
| 3       | 1             | Editor → read           |
| 3       | 3             | Editor → update         |
| 4       | 1             | Viewer → read           |

## Person ↔ Service ↔ Role links (`auth.person_service_role`)
| person_id | service_id | role_id | note                         |
| --------- | ---------- | ------- | ---------------------------- |
| 1         | 1          | 1       | adm1 is Admin in Service A   |
| 2         | 1          | 2       | usr1 is User in Service A    |
| 3         | 2          | 2       | usr2 is User in Service B    |
| 4         | 3          | 3       | usr3 is Editor in Service C  |
| 7         | 4          | 4       | juan is Viewer in UI Store   |

Use these IDs for quick manual requests (e.g., `GET /people/7/services/4` with `token` from user `juan`). Refresh by running `psql -U postgres -f db/run_all.sql`.
