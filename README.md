# EQEQO API AUTH

Servicio central de identidad y autorizacion para Eqeqo.

## Alcance

- Gestiona usuarios, negocios, servicios, roles, permisos, sesiones y settings por app.
- Emite y renueva tokens cortos en `auth.tokens_cache`.
- Expone `/check-permission` para que POS y APIs validen permisos por negocio y servicio.
- No guarda datos comerciales, stock ni ventas.

## Runtime

```env
AUTH_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/api_auth?options=-c%20search_path%3Dauth
MAX_CONNECTIONS=5
USER_TOKEN_TTL_SECONDS=300
TOKEN_RENEW_THRESHOLD_SECONDS=30
```

Servidor local por defecto: `127.0.0.1:7878`.

## Comandos

```sh
cp .env-example .env
set -a; . ./.env; set +a
sudo --preserve-env=AUTH_DATABASE_URL -u postgres psql -f db/run_all.sql
cargo run
cargo test
sudo bash deploy/deploy.sh
```

`db/run_all.sql` recrea la BD. Para refrescar solo permisos/usuarios demo POS, ejecutar `db/authorization_seed.sql`; es idempotente.

## Base de Datos

- PostgreSQL guarda usuarios, negocios, servicios, roles, permisos, sesiones, cache de permisos y settings.
- `db/structure.sql` define tablas, tipos e indices.
- `db/procedures.sql` contiene la logica SQL actual.
- Rust solo llama funciones/procedimientos `auth.*`; no debe consultar tablas directamente.
- `auth.default_business_id()` usa `RUC 00000000001` como negocio demo; si no existe, usa el primer negocio activo para endpoints legacy.

Flujo interno:

1. Handler valida token/header/body.
2. Handler llama rutinas `auth.*` para leer o escribir datos.
3. Si cambia acceso, se invalida cache de permisos.
4. La respuesta HTTP se arma en Rust.

## Autorizacion

- Rutas protegidas: header `user-token`.
- Frontend/POS: `POST /check-permission` con `{ "business_id": 1, "service_id": "pos" }`.
- Backend seguro: `user-token` + `service-token`, body `{ "business_id": 1 }`.
- `service_id` acepta nombre corto (`pos`, `api-sales`) o ID numerico.
- Tokens no deben ir en URL.

## POS

Flujo minimo:

1. `POST /auth/login`.
2. `GET /me` con `user-token`; si ya hay negocio activo, enviar `business-id` y `app-id: pos`.
3. Elegir negocio activo.
4. `POST /check-permission` para `service_id: "pos"`.
5. POS guarda `roles` y `permissions`; las APIs backend vuelven a validar permisos propios.

Usuarios demo POS: ver `db/DB.md`.

## Endpoints

| Metodo | Ruta | Uso |
| --- | --- | --- |
| POST | `/auth/login` | Login y token. |
| POST | `/auth/register` | Registro publico. |
| POST | `/auth/logout` | Revocar token actual. |
| GET | `/auth/profile` | Validar/renovar token. |
| GET | `/me` | Contexto inicial de UI: usuario, negocios, negocio activo y settings. |
| PATCH | `/me/settings` | Actualizar settings por negocio/app. |
| POST | `/check-permission` | Validar acceso por negocio y servicio. |
| GET/POST | `/me/businesses` | Listar o crear negocio del usuario actual. |
| GET/POST/PUT/DELETE | `/businesses` | Administrar negocios. |
| GET/POST/PUT/DELETE | `/users` | Administrar usuarios. |
| GET/POST/PUT/DELETE | `/services` | Administrar servicios. |
| GET/POST/PUT/DELETE | `/roles` | Administrar roles. |
| GET/POST/PUT/DELETE | `/permissions` | Administrar permisos. |
| POST/DELETE | `/role-permissions` | Vincular permisos a roles. |
| POST/DELETE | `/service-roles` | Vincular roles a servicios. |
| POST/DELETE | `/person-service-roles` | Asignar roles por persona, negocio y servicio. |
| POST | `/person-service-permissions` | Otorgar permiso directo por persona. |
| POST | `/business-invitations` | Crear invitacion de negocio. |
| POST | `/business-invitations/accept` | Aceptar invitacion. |

## Referencias

- Datos seed y usuarios: `db/DB.md`.
- Matriz POS: `db/POS_ROLE_PERMISSION_MATRIX.md`.
- Produccion: `deploy/PRODUCTION.md`.
- Servicio systemd: `deploy/api-auth.service`.
