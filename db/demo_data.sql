-- Demo seed data for the auth API database.
-- All inserts use ON CONFLICT safeguards so the script can be run multiple times.

\set ON_ERROR_STOP on

-- Services
INSERT INTO auth.services (name, description)
VALUES
  ('Service A', 'Demo catalog service'),
  ('Service B', 'Internal billing service'),
  ('Service C', 'Customer support portal'),
  ('UI Store', 'Frontend store surface')
ON CONFLICT (name) DO NOTHING;

-- Roles
INSERT INTO auth.role (name)
VALUES
  ('Admin'),
  ('User'),
  ('Editor'),
  ('Viewer')
ON CONFLICT (name) DO NOTHING;

-- Permissions
INSERT INTO auth.permission (name)
VALUES
  ('read'),
  ('write'),
  ('update'),
  ('delete'),
  ('share')
ON CONFLICT (name) DO NOTHING;

-- People
INSERT INTO auth.person (
  username,
  password_hash,
  name,
  person_type,
  document_type,
  document_number
)
VALUES
  ('adm1', 'adm1-hash', 'Admin One', 'N', 'DNI', '00000001'),
  ('usr1', 'usr1-hash', 'User One', 'N', 'DNI', '00000002'),
  ('usr2', 'usr2-hash', 'User Two', 'N', 'DNI', '00000003'),
  ('usr3', 'usr3-hash', 'User Three', 'N', 'DNI', '00000004'),
  ('editor1', 'editor1-hash', 'Editor One', 'N', 'DNI', '00000005'),
  ('viewer1', 'viewer1-hash', 'Viewer One', 'N', 'DNI', '00000006'),
  ('juan', 'juan-hash', 'Juan Demo', 'N', 'DNI', '00000007')
ON CONFLICT (username) DO NOTHING;

-- Service roles
WITH service_role_pairs (service_name, role_name) AS (
  VALUES
    ('Service A', 'Admin'),
    ('Service A', 'User'),
    ('Service B', 'User'),
    ('Service C', 'Editor'),
    ('UI Store', 'Viewer')
)
INSERT INTO auth.service_roles (service_id, role_id)
SELECT s.id, r.id
FROM service_role_pairs sr
JOIN auth.services s ON s.name = sr.service_name
JOIN auth.role r ON r.name = sr.role_name
ON CONFLICT (service_id, role_id) DO NOTHING;

-- Role permissions
WITH role_permission_pairs (role_name, permission_name) AS (
  VALUES
    ('Admin', 'read'),
    ('Admin', 'write'),
    ('Admin', 'update'),
    ('Admin', 'delete'),
    ('User', 'read'),
    ('Editor', 'update'),
    ('Editor', 'read'),
    ('Viewer', 'read')
)
INSERT INTO auth.role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role_permission_pairs rpp
JOIN auth.role r ON r.name = rpp.role_name
JOIN auth.permission p ON p.name = rpp.permission_name
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Person assignments to service roles
WITH person_service_role_pairs (username, service_name, role_name) AS (
  VALUES
    ('adm1', 'Service A', 'Admin'),
    ('usr1', 'Service A', 'User'),
    ('usr2', 'Service B', 'User'),
    ('usr3', 'Service C', 'Editor'),
    ('juan', 'UI Store', 'Viewer')
)
INSERT INTO auth.person_service_role (person_id, service_id, role_id)
SELECT pe.id, s.id, r.id
FROM person_service_role_pairs psr
JOIN auth.person pe ON pe.username = psr.username
JOIN auth.services s ON s.name = psr.service_name
JOIN auth.role r ON r.name = psr.role_name
ON CONFLICT (person_id, service_id, role_id) DO NOTHING;
