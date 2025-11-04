-- Procedures and functions for the auth schema

-- Person management
CREATE OR REPLACE FUNCTION auth.create_person(
    p_username TEXT,
    p_password_hash TEXT,
    p_name TEXT,
    p_person_type auth.person_type,
    p_document_type auth.document_type,
    p_document_number TEXT
)
RETURNS TABLE(id INT, username TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    INSERT INTO auth.person (username, password_hash, name, person_type, document_type, document_number)
    VALUES (p_username, p_password_hash, p_name, p_person_type, p_document_type, p_document_number)
    RETURNING auth.person.id, auth.person.username, auth.person.name;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_people()
RETURNS TABLE(id INT, username TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.username, p.name
    FROM auth.person p
    WHERE p.removed_at IS NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.get_person(p_id INT)
RETURNS TABLE(id INT, username TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.username, p.name
    FROM auth.person p
    WHERE p.id = p_id
      AND p.removed_at IS NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.update_person(
    p_id INT,
    p_username TEXT,
    p_password_hash TEXT,
    p_name TEXT
) AS $$
BEGIN
    UPDATE auth.person
    SET
        username = COALESCE(p_username, username),
        password_hash = COALESCE(p_password_hash, password_hash),
        name = COALESCE(p_name, name)
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.delete_person(p_id INT) AS $$
BEGIN
    UPDATE auth.person
    SET removed_at = EXTRACT(EPOCH FROM NOW())::BIGINT
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

-- Role management
CREATE OR REPLACE FUNCTION auth.create_role(p_name TEXT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    INSERT INTO auth.role (name)
    VALUES (p_name)
    ON CONFLICT ON CONSTRAINT role_name_key DO NOTHING;

    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r
    WHERE r.name = p_name;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_roles()
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.get_role(p_id INT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r
    WHERE r.id = p_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.update_role(p_id INT, p_name TEXT) AS $$
BEGIN
    UPDATE auth.role
    SET name = COALESCE(p_name, name)
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.delete_role(p_id INT) AS $$
BEGIN
    DELETE FROM auth.role WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

-- Permission management
CREATE OR REPLACE FUNCTION auth.create_permission(p_name TEXT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    INSERT INTO auth.permission (name)
    VALUES (p_name)
    ON CONFLICT ON CONSTRAINT permission_name_key DO NOTHING;

    RETURN QUERY
    SELECT p.id, p.name
    FROM auth.permission p
    WHERE p.name = p_name;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_permissions()
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.name
    FROM auth.permission p;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.update_permission(p_id INT, p_name TEXT) AS $$
BEGIN
    UPDATE auth.permission
    SET name = COALESCE(p_name, name)
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.delete_permission(p_id INT) AS $$
BEGIN
    DELETE FROM auth.permission WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

-- Service management
CREATE OR REPLACE FUNCTION auth.create_service(p_name TEXT, p_description TEXT)
RETURNS TABLE(id INT, name TEXT, description TEXT) AS $$
BEGIN
    RETURN QUERY
    WITH upsert AS (
        INSERT INTO auth.services (name, description)
        VALUES (p_name, p_description)
        ON CONFLICT ON CONSTRAINT services_name_key DO UPDATE
        SET
            description = EXCLUDED.description,
            updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT
        RETURNING auth.services.id AS id,
                  auth.services.name AS name,
                  auth.services.description AS description
    )
    SELECT upsert.id, upsert.name, upsert.description FROM upsert
    UNION ALL
    SELECT s.id, s.name, s.description
    FROM auth.services s
    WHERE s.name = p_name
      AND NOT EXISTS (SELECT 1 FROM upsert);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_services()
RETURNS TABLE(id INT, name TEXT, description TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT s.id, s.name, s.description
    FROM auth.services s
    WHERE s.status = TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.update_service(p_id INT, p_name TEXT, p_description TEXT) AS $$
BEGIN
    UPDATE auth.services
    SET
        name = COALESCE(p_name, name),
        description = COALESCE(p_description, description)
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.delete_service(p_id INT) AS $$
BEGIN
    UPDATE auth.services
    SET status = FALSE
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;

-- Role-permission relationships
CREATE OR REPLACE PROCEDURE auth.assign_permission_to_role(p_role_id INT, p_permission_id INT) AS $$
BEGIN
    INSERT INTO auth.role_permission (role_id, permission_id)
    VALUES (p_role_id, p_permission_id)
    ON CONFLICT (role_id, permission_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_permission_from_role(p_role_id INT, p_permission_id INT) AS $$
BEGIN
    DELETE FROM auth.role_permission
    WHERE role_id = p_role_id
      AND permission_id = p_permission_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_role_permissions(p_role_id INT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.name
    FROM auth.permission p
    JOIN auth.role_permission rp ON p.id = rp.permission_id
    WHERE rp.role_id = p_role_id;
END;
$$ LANGUAGE plpgsql;

-- Service-role relationships
CREATE OR REPLACE PROCEDURE auth.assign_role_to_service(p_service_id INT, p_role_id INT) AS $$
BEGIN
    INSERT INTO auth.service_roles (service_id, role_id)
    VALUES (p_service_id, p_role_id)
    ON CONFLICT (service_id, role_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_role_from_service(p_service_id INT, p_role_id INT) AS $$
BEGIN
    DELETE FROM auth.service_roles
    WHERE service_id = p_service_id
      AND role_id = p_role_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_service_roles(p_service_id INT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r
    JOIN auth.service_roles sr ON r.id = sr.role_id
    WHERE sr.service_id = p_service_id;
END;
$$ LANGUAGE plpgsql;

-- Person assignments to service roles
CREATE OR REPLACE PROCEDURE auth.assign_role_to_person_in_service(p_person_id INT, p_service_id INT, p_role_id INT) AS $$
BEGIN
    INSERT INTO auth.person_service_role (person_id, service_id, role_id)
    VALUES (p_person_id, p_service_id, p_role_id)
    ON CONFLICT (person_id, service_id, role_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_role_from_person_in_service(p_person_id INT, p_service_id INT, p_role_id INT) AS $$
BEGIN
    DELETE FROM auth.person_service_role
    WHERE person_id = p_person_id
      AND service_id = p_service_id
      AND role_id = p_role_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_person_roles_in_service(p_person_id INT, p_service_id INT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r
    JOIN auth.person_service_role psr ON r.id = psr.role_id
    WHERE psr.person_id = p_person_id
      AND psr.service_id = p_service_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_persons_with_role_in_service(p_service_id INT, p_role_id INT)
RETURNS TABLE(id INT, username TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.username, p.name
    FROM auth.person p
    JOIN auth.person_service_role psr ON p.id = psr.person_id
    WHERE psr.service_id = p_service_id
      AND psr.role_id = p_role_id
      AND p.removed_at IS NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.check_person_permission_in_service(p_person_id INT, p_service_id INT, p_permission_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM auth.person_service_role psr
        JOIN auth.role_permission rp ON psr.role_id = rp.role_id
        JOIN auth.permission p ON rp.permission_id = p.id
        WHERE psr.person_id = p_person_id
          AND psr.service_id = p_service_id
          AND p.name = p_permission_name
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_services_of_person(p_person_id INT)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT s.id, s.name
    FROM auth.services s
    JOIN auth.person_service_role psr ON s.id = psr.service_id
    WHERE psr.person_id = p_person_id
      AND s.status = TRUE;
END;
$$ LANGUAGE plpgsql;
