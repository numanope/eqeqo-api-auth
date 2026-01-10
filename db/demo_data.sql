-- Demo seed data for the auth API database.
-- All inserts use ON CONFLICT safeguards so the script can be run multiple times.

\set ON_ERROR_STOP on

-- Services
INSERT INTO auth.services (name, description)
VALUES
  ('Service A', 'Demo catalog service'),
  ('Service B', 'Internal billing service'),
  ('Service C', 'Customer support portal'),
  ('UI Store', 'Frontend store surface'),
  ('ui-store', 'Frontend store surface')
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
  ('adm1', '$2y$10$BlkGXSHqs7UlEU.nOsTCpeNwDcMbcDatkphwh0zSrz8nNDuwLVkk6', 'Admin One', 'N', 'DNI', '00000001'),
  ('usr1', '$2y$10$9f9i/MotJh9KDol./GJUFef.TKbxMNCX2JmsK3tctUrqD0F0VJR4i', 'User One', 'N', 'DNI', '00000002'),
  ('usr2', '$2y$10$wMZn9yjfksl01TU2hl6l0uj.tmW7wLdix6Zfh1/CRCgqClNcCCGWu', 'User Two', 'N', 'DNI', '00000003'),
  ('usr3', '$2y$10$uYjanE5Ual5x21Yg.cX.SuqF7fhA7Dw.1Itdx5OpgPhMjKj2iBuM.', 'User Three', 'N', 'DNI', '00000004'),
  ('editor1', '$2y$10$fm3wYlopoUKCkeQBtmTwq.Xl8s08nckqqPy8SLhQv3OPt3IcVWgy2', 'Editor One', 'N', 'DNI', '00000005'),
  ('viewer1', '$2y$10$C5TXgBV4zcd7Y1Hh4TEAVen8cOVa9HwkCcxWf4OMJmELUrzMLXthe', 'Viewer One', 'N', 'DNI', '00000006'),
  ('juan', '$2y$10$wIhDH3w2i0JlcHDObQEhWOKo4BqTVkoqLOQCr00FCmXOs.zliMmTW', 'Juan Demo', 'N', 'DNI', '00000007'),
  ('adm2', '$2y$10$SWM.3.RJ0HZuaLO6K2cQnOH333kI3aAZ0dciKS0ygzpKSXhTaMLZO', 'Admin Two', 'N', 'DNI', '00000008'),
  ('adm3', '$2y$10$wfdK67UPuB0m/0Q44joQROgTkFoVIHZUxlkbKLwmmXwloMA298Roa', 'Admin Three', 'N', 'DNI', '00000009'),
  ('usr4', '$2y$10$Uyf1CyJSImwd36zlmlVpOeAsN1tb7JHsZBDAP8FAl95eFEIfkaIQi', 'User Four', 'N', 'DNI', '00000010'),
  ('usr5', '$2y$10$3gcUmchkgmEbMI1aznCHxOvHg.71s/p9ugLH/FwFlzHTE4AYUddry', 'User Five', 'N', 'DNI', '00000011'),
  ('editor2', '$2y$10$4AVVxU9kJnD0EAFa1C.U0eOJLMV.94LJB0HYXZuGVLROZ6nsf5O4e', 'Editor Two', 'N', 'DNI', '00000012'),
  ('editor3', '$2y$10$IOOvfUEOomm8Zta1mxvs..B3/4TeOmX8OSTQdG/BlA6otIbdz7N0S', 'Editor Three', 'N', 'DNI', '00000013'),
  ('viewer2', '$2y$10$RLjCvLFpfLSC3MiObka4UeEeNZ0/aRIXLMku1z6dvtoFDxJEpi18y', 'Viewer Two', 'N', 'DNI', '00000014'),
  ('viewer3', '$2y$10$ozVtHHcWPEhSxJPlIPGXNejQVv/ni2yS/CNJThh1j8Hua5G78cSKO', 'Viewer Three', 'N', 'DNI', '00000015')
ON CONFLICT (username) DO NOTHING;

UPDATE auth.person
SET can_register_services = TRUE
WHERE username IN ('adm1');

-- Service roles
WITH service_role_pairs (service_name, role_name) AS (
  VALUES
    ('Service A', 'Admin'),
    ('Service A', 'User'),
    ('Service B', 'User'),
    ('Service C', 'Editor'),
    ('UI Store', 'Viewer'),
    ('UI Store', 'Admin'),
    ('UI Store', 'User'),
    ('UI Store', 'Editor'),
    ('ui-store', 'Viewer')
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
    ('User', 'write'),
    ('User', 'update'),
    ('User', 'delete'),
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
    ('editor1', 'Service A', 'Admin'),
    ('editor1', 'Service C', 'Editor'),
    ('viewer1', 'ui-store', 'Viewer'),
    ('juan', 'UI Store', 'Viewer'),
    ('adm2', 'UI Store', 'Admin'),
    ('adm3', 'UI Store', 'Admin'),
    ('usr4', 'UI Store', 'User'),
    ('usr5', 'UI Store', 'User'),
    ('editor2', 'UI Store', 'Editor'),
    ('editor3', 'UI Store', 'Editor'),
    ('viewer2', 'UI Store', 'Viewer'),
    ('viewer3', 'UI Store', 'Viewer')
)
INSERT INTO auth.person_service_role (person_id, service_id, role_id)
SELECT pe.id, s.id, r.id
FROM person_service_role_pairs psr
JOIN auth.person pe ON pe.username = psr.username
JOIN auth.services s ON s.name = psr.service_name
JOIN auth.role r ON r.name = psr.role_name
ON CONFLICT (person_id, service_id, role_id) DO NOTHING;
