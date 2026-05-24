# POS Role Permission Matrix

Fuente: `db/authorization_seed.sql`.

## Test Users

Todos usan password `<username>-hash`.

| Role | Username |
| ---- | -------- |
| Owner | adm2 |
| Manager | adm3 |
| Cashier | usr4 |
| Stock | editor2 |
| Purchase | editor3 |
| Accounting | usr5 |
| Auditor | viewer2 |
| Support | viewer3 |

## Permission Matrix

`x` significa que el rol tiene el permiso.

| Permission | Owner | Manager | Cashier | Stock | Purchase | Accounting | Auditor | Support |
| ---------- | ----- | ------- | ------- | ----- | -------- | ---------- | ------- | ------- |
| sales.read | x | x | x |  |  | x | x | x |
| sales.create | x | x | x |  |  |  |  |  |
| sales.update | x | x |  |  |  |  |  |  |
| sales.cancel | x | x |  |  |  | x |  |  |
| sales.refund | x | x |  |  |  | x |  |  |
| quotes.create | x | x | x |  |  |  |  |  |
| cash.read | x | x | x |  |  | x | x |  |
| cash.open | x | x | x |  |  |  |  |  |
| cash.close | x | x | x |  |  | x |  |  |
| cash.move | x | x |  |  |  | x |  |  |
| products.read | x | x | x | x | x |  | x | x |
| products.create | x | x |  | x |  |  |  |  |
| products.update | x | x |  | x |  |  |  |  |
| products.delete | x |  |  | x |  |  |  |  |
| stock.read | x | x | x | x | x |  | x | x |
| stock.move | x | x |  | x |  |  |  |  |
| stock.adjust | x | x |  | x |  |  |  |  |
| purchases.read | x | x |  |  | x | x | x |  |
| purchases.create | x | x |  |  | x |  |  |  |
| purchases.update | x | x |  |  | x |  |  |  |
| purchases.cancel | x |  |  |  | x |  |  |  |
| contacts.read | x | x | x |  | x |  | x | x |
| contacts.create | x | x | x |  | x |  |  |  |
| contacts.update | x | x |  |  | x |  |  |  |
| contacts.delete | x |  |  |  |  |  |  |  |
| reports.read | x | x |  | x | x | x | x |  |
| reports.export | x | x |  |  |  | x | x |  |
| users.read | x | x |  |  |  |  |  |  |
| users.invite | x | x |  |  |  |  |  |  |
| users.update | x |  |  |  |  |  |  |  |
| users.delete | x |  |  |  |  |  |  |  |
| roles.read | x |  |  |  |  |  |  |  |
| roles.update | x |  |  |  |  |  |  |  |
| settings.read | x | x |  |  |  |  |  | x |
| settings.update | x | x |  |  |  |  |  |  |
| tax.read | x | x |  |  |  | x | x |  |
| tax.send | x | x |  |  |  | x |  |  |
| tax.cancel | x |  |  |  |  | x |  |  |
| payments.read | x | x | x |  |  | x | x |  |
| payments.create | x | x | x |  |  |  |  |  |
| payments.refund | x |  |  |  |  | x |  |  |

## Frontend Test Approach

Actualmente `pos` no tiene runner de pruebas frontend; solo tiene `npm run check` y `npm run build`.

Forma recomendada para automatizar:

1. Unit test de reglas puras: validar que `routePermissions` abre/cierra rutas segun una lista de permisos simulada.
2. E2E con navegador: login con cada usuario de prueba y verificar menu/rutas visibles.
3. Backend check previo: para cada usuario, llamar `/check-permission` y comparar permisos contra esta matriz.

El primer paso mas barato es extraer el calculo de visibilidad de rutas a una funcion pura y probarla sin navegador. El E2E con Playwright conviene despues, cuando el flujo de login/negocio este estable.
