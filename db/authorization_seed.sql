-- Minimal authorization seed for POS and API permissions.
-- This file only inserts data. It does not change database structure.
-- It is safe to run more than once.

\set ON_ERROR_STOP on

-- Services/apps. Names stay short because users may register their own apps.
INSERT INTO auth.services (name, description)
VALUES
  ('pos', 'Point of sale app'),
  ('api-auth', 'Authorization API'),
  ('api-sales', 'Sales API'),
  ('api-stocks', 'Stocks API'),
  ('api-commercial', 'Commercial API')
ON CONFLICT (name) DO UPDATE
SET
  description = COALESCE(EXCLUDED.description, auth.services.description),
  updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;

-- User-facing roles.
INSERT INTO auth.role (name)
VALUES
  ('Owner'),
  ('Manager'),
  ('Cashier'),
  ('Stock'),
  ('Purchase'),
  ('Accounting'),
  ('Auditor'),
  ('Support')
ON CONFLICT (name) DO NOTHING;

-- Minimal action names. The service/app gives the context.
INSERT INTO auth.permission (name)
VALUES
  ('sales.read'),
  ('sales.create'),
  ('sales.update'),
  ('sales.cancel'),
  ('sales.refund'),
  ('quotes.create'),
  ('cash.read'),
  ('cash.open'),
  ('cash.close'),
  ('cash.move'),
  ('products.read'),
  ('products.create'),
  ('products.update'),
  ('products.delete'),
  ('stock.read'),
  ('stock.move'),
  ('stock.adjust'),
  ('purchases.read'),
  ('purchases.create'),
  ('purchases.update'),
  ('purchases.cancel'),
  ('contacts.read'),
  ('contacts.create'),
  ('contacts.update'),
  ('contacts.delete'),
  ('reports.read'),
  ('reports.export'),
  ('users.read'),
  ('users.invite'),
  ('users.update'),
  ('users.delete'),
  ('roles.read'),
  ('roles.update'),
  ('settings.read'),
  ('settings.update'),
  ('tax.read'),
  ('tax.send'),
  ('tax.cancel'),
  ('payments.read'),
  ('payments.create'),
  ('payments.refund')
ON CONFLICT (name) DO NOTHING;

-- Role to permission defaults.
WITH role_permission_pairs (role_name, permission_name) AS (
  VALUES
    -- Owner: all seeded permissions.
    ('Owner', 'sales.read'),
    ('Owner', 'sales.create'),
    ('Owner', 'sales.update'),
    ('Owner', 'sales.cancel'),
    ('Owner', 'sales.refund'),
    ('Owner', 'quotes.create'),
    ('Owner', 'cash.read'),
    ('Owner', 'cash.open'),
    ('Owner', 'cash.close'),
    ('Owner', 'cash.move'),
    ('Owner', 'products.read'),
    ('Owner', 'products.create'),
    ('Owner', 'products.update'),
    ('Owner', 'products.delete'),
    ('Owner', 'stock.read'),
    ('Owner', 'stock.move'),
    ('Owner', 'stock.adjust'),
    ('Owner', 'purchases.read'),
    ('Owner', 'purchases.create'),
    ('Owner', 'purchases.update'),
    ('Owner', 'purchases.cancel'),
    ('Owner', 'contacts.read'),
    ('Owner', 'contacts.create'),
    ('Owner', 'contacts.update'),
    ('Owner', 'contacts.delete'),
    ('Owner', 'reports.read'),
    ('Owner', 'reports.export'),
    ('Owner', 'users.read'),
    ('Owner', 'users.invite'),
    ('Owner', 'users.update'),
    ('Owner', 'users.delete'),
    ('Owner', 'roles.read'),
    ('Owner', 'roles.update'),
    ('Owner', 'settings.read'),
    ('Owner', 'settings.update'),
    ('Owner', 'tax.read'),
    ('Owner', 'tax.send'),
    ('Owner', 'tax.cancel'),
    ('Owner', 'payments.read'),
    ('Owner', 'payments.create'),
    ('Owner', 'payments.refund'),

    -- Manager: daily operation, no user/role destructive control.
    ('Manager', 'sales.read'),
    ('Manager', 'sales.create'),
    ('Manager', 'sales.update'),
    ('Manager', 'sales.cancel'),
    ('Manager', 'sales.refund'),
    ('Manager', 'quotes.create'),
    ('Manager', 'cash.read'),
    ('Manager', 'cash.open'),
    ('Manager', 'cash.close'),
    ('Manager', 'cash.move'),
    ('Manager', 'products.read'),
    ('Manager', 'products.create'),
    ('Manager', 'products.update'),
    ('Manager', 'stock.read'),
    ('Manager', 'stock.move'),
    ('Manager', 'stock.adjust'),
    ('Manager', 'purchases.read'),
    ('Manager', 'purchases.create'),
    ('Manager', 'purchases.update'),
    ('Manager', 'contacts.read'),
    ('Manager', 'contacts.create'),
    ('Manager', 'contacts.update'),
    ('Manager', 'reports.read'),
    ('Manager', 'reports.export'),
    ('Manager', 'users.read'),
    ('Manager', 'users.invite'),
    ('Manager', 'settings.read'),
    ('Manager', 'settings.update'),
    ('Manager', 'tax.read'),
    ('Manager', 'tax.send'),
    ('Manager', 'payments.read'),
    ('Manager', 'payments.create'),

    -- Cashier: sales and own cash operations.
    ('Cashier', 'sales.read'),
    ('Cashier', 'sales.create'),
    ('Cashier', 'quotes.create'),
    ('Cashier', 'cash.read'),
    ('Cashier', 'cash.open'),
    ('Cashier', 'cash.close'),
    ('Cashier', 'contacts.read'),
    ('Cashier', 'contacts.create'),
    ('Cashier', 'products.read'),
    ('Cashier', 'stock.read'),
    ('Cashier', 'payments.read'),
    ('Cashier', 'payments.create'),

    -- Stock: product and inventory operations.
    ('Stock', 'products.read'),
    ('Stock', 'products.create'),
    ('Stock', 'products.update'),
    ('Stock', 'products.delete'),
    ('Stock', 'stock.read'),
    ('Stock', 'stock.move'),
    ('Stock', 'stock.adjust'),
    ('Stock', 'reports.read'),

    -- Purchase: providers and purchases.
    ('Purchase', 'products.read'),
    ('Purchase', 'stock.read'),
    ('Purchase', 'purchases.read'),
    ('Purchase', 'purchases.create'),
    ('Purchase', 'purchases.update'),
    ('Purchase', 'purchases.cancel'),
    ('Purchase', 'contacts.read'),
    ('Purchase', 'contacts.create'),
    ('Purchase', 'contacts.update'),
    ('Purchase', 'reports.read'),

    -- Accounting: money, tax and reports.
    ('Accounting', 'sales.read'),
    ('Accounting', 'sales.cancel'),
    ('Accounting', 'sales.refund'),
    ('Accounting', 'cash.read'),
    ('Accounting', 'cash.close'),
    ('Accounting', 'cash.move'),
    ('Accounting', 'purchases.read'),
    ('Accounting', 'reports.read'),
    ('Accounting', 'reports.export'),
    ('Accounting', 'tax.read'),
    ('Accounting', 'tax.send'),
    ('Accounting', 'tax.cancel'),
    ('Accounting', 'payments.read'),
    ('Accounting', 'payments.refund'),

    -- Auditor: read-only plus exports.
    ('Auditor', 'sales.read'),
    ('Auditor', 'cash.read'),
    ('Auditor', 'products.read'),
    ('Auditor', 'stock.read'),
    ('Auditor', 'purchases.read'),
    ('Auditor', 'contacts.read'),
    ('Auditor', 'reports.read'),
    ('Auditor', 'reports.export'),
    ('Auditor', 'tax.read'),
    ('Auditor', 'payments.read'),

    -- Support: enough to diagnose, not operate money.
    ('Support', 'sales.read'),
    ('Support', 'products.read'),
    ('Support', 'stock.read'),
    ('Support', 'contacts.read'),
    ('Support', 'settings.read')
)
INSERT INTO auth.role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role_permission_pairs rp
JOIN auth.role r ON r.name = rp.role_name
JOIN auth.permission p ON p.name = rp.permission_name
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Make the roles available to the known app/API services.
WITH service_role_pairs (service_name, role_name) AS (
  VALUES
    ('pos', 'Owner'),
    ('pos', 'Manager'),
    ('pos', 'Cashier'),
    ('pos', 'Stock'),
    ('pos', 'Purchase'),
    ('pos', 'Accounting'),
    ('pos', 'Auditor'),
    ('pos', 'Support'),
    ('api-auth', 'Owner'),
    ('api-auth', 'Manager'),
    ('api-auth', 'Support'),
    ('api-sales', 'Owner'),
    ('api-sales', 'Manager'),
    ('api-sales', 'Cashier'),
    ('api-sales', 'Purchase'),
    ('api-sales', 'Accounting'),
    ('api-sales', 'Auditor'),
    ('api-sales', 'Support'),
    ('api-stocks', 'Owner'),
    ('api-stocks', 'Manager'),
    ('api-stocks', 'Stock'),
    ('api-stocks', 'Purchase'),
    ('api-stocks', 'Auditor'),
    ('api-stocks', 'Support'),
    ('api-commercial', 'Owner'),
    ('api-commercial', 'Manager'),
    ('api-commercial', 'Cashier'),
    ('api-commercial', 'Purchase'),
    ('api-commercial', 'Accounting'),
    ('api-commercial', 'Auditor'),
    ('api-commercial', 'Support')
)
INSERT INTO auth.service_roles (service_id, role_id)
SELECT s.id, r.id
FROM service_role_pairs sr
JOIN auth.services s ON s.name = sr.service_name
JOIN auth.role r ON r.name = sr.role_name
ON CONFLICT (service_id, role_id) DO NOTHING;

-- Demo POS users for testing each role.
WITH pos_role_users (username, role_name) AS (
  VALUES
    ('adm2', 'Owner'),
    ('adm3', 'Manager'),
    ('usr4', 'Cashier'),
    ('editor2', 'Stock'),
    ('editor3', 'Purchase'),
    ('usr5', 'Accounting'),
    ('viewer2', 'Auditor'),
    ('viewer3', 'Support')
)
INSERT INTO auth.business_users (business_id, person_id)
SELECT b.id, pe.id
FROM pos_role_users pru
JOIN auth.person pe ON pe.username = pru.username
CROSS JOIN LATERAL (
  SELECT id
  FROM auth.businesses
  WHERE status = TRUE
    AND removed_at IS NULL
  ORDER BY
    CASE
      WHEN document_type = 'RUC' AND document_number = '00000000001' THEN 0
      ELSE 1
    END,
    id
  LIMIT 1
) b
ON CONFLICT (business_id, person_id) DO NOTHING;

WITH pos_role_users (username, role_name) AS (
  VALUES
    ('adm2', 'Owner'),
    ('adm3', 'Manager'),
    ('usr4', 'Cashier'),
    ('editor2', 'Stock'),
    ('editor3', 'Purchase'),
    ('usr5', 'Accounting'),
    ('viewer2', 'Auditor'),
    ('viewer3', 'Support')
)
INSERT INTO auth.person_service_role (business_id, person_id, service_id, role_id)
SELECT b.id, pe.id, s.id, r.id
FROM pos_role_users pru
JOIN auth.person pe ON pe.username = pru.username
JOIN auth.services s ON s.name = 'pos'
JOIN auth.role r ON r.name = pru.role_name
CROSS JOIN LATERAL (
  SELECT id
  FROM auth.businesses
  WHERE status = TRUE
    AND removed_at IS NULL
  ORDER BY
    CASE
      WHEN document_type = 'RUC' AND document_number = '00000000001' THEN 0
      ELSE 1
    END,
    id
  LIMIT 1
) b
ON CONFLICT (business_id, person_id, service_id, role_id) DO NOTHING;
