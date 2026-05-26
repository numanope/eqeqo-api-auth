-- Procedures and functions for the auth schema

-- Token and access cache
CREATE OR REPLACE PROCEDURE auth.sp_tokens_insert(
    p_token TEXT,
    p_payload JSONB,
    p_expires_at BIGINT
) AS $$
BEGIN
    INSERT INTO auth.tokens_cache (token, payload, expires_at)
    VALUES (p_token, p_payload, p_expires_at);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_tokens_get(p_token TEXT)
RETURNS TABLE(token TEXT, payload JSONB, expires_at BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT tc.token, tc.payload, tc.expires_at
    FROM auth.tokens_cache tc
    WHERE tc.token = p_token;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_tokens_touch(
    p_token TEXT,
    p_previous_expires_at BIGINT,
    p_new_expires_at BIGINT
) RETURNS TABLE(token TEXT, payload JSONB, expires_at BIGINT) AS $$
BEGIN
    RETURN QUERY
    UPDATE auth.tokens_cache tc
    SET expires_at = p_new_expires_at
    WHERE tc.token = p_token
      AND tc.expires_at = p_previous_expires_at
    RETURNING tc.token, tc.payload, tc.expires_at;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_tokens_delete(p_token TEXT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.tokens_cache WHERE token = p_token;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_tokens_delete_for_user(p_user_id TEXT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.tokens_cache WHERE payload ->> 'user_id' = p_user_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_access_cache_delete(
    p_user_id TEXT,
    p_business_id INT,
    p_service_id INT
) RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.permissions_cache
    WHERE token IN (
        SELECT token FROM auth.tokens_cache WHERE payload ->> 'user_id' = p_user_id
    )
      AND business_id = p_business_id
      AND service_id = p_service_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_access_cache_delete_for_user(p_user_id TEXT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.permissions_cache
    WHERE token IN (
        SELECT token FROM auth.tokens_cache WHERE payload ->> 'user_id' = p_user_id
    );
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_access_cache_delete_for_service(p_service_id INT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.permissions_cache WHERE service_id = p_service_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_access_cache_clear()
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    DELETE FROM auth.permissions_cache;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_access_cache_get(
    p_token TEXT,
    p_business_id INT,
    p_service_id INT
) RETURNS TABLE(access_json JSONB, expires_at BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT permissions AS access_json, pc.expires_at
    FROM auth.permissions_cache pc
    WHERE token = p_token
      AND business_id = p_business_id
      AND service_id = p_service_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.sp_access_cache_store(
    p_token TEXT,
    p_business_id INT,
    p_service_id INT,
    p_access_json JSONB,
    p_expires_at BIGINT
) AS $$
BEGIN
    INSERT INTO auth.permissions_cache (token, business_id, service_id, permissions, expires_at)
    VALUES (p_token, p_business_id, p_service_id, p_access_json, p_expires_at)
    ON CONFLICT (token, business_id, service_id)
    DO UPDATE SET permissions = EXCLUDED.permissions,
                  expires_at = EXCLUDED.expires_at;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_cache_cleanup_expired(p_now BIGINT)
RETURNS BIGINT AS $$
DECLARE
    v_token_rows BIGINT;
    v_permission_rows BIGINT;
BEGIN
    DELETE FROM auth.tokens_cache WHERE expires_at < p_now;
    GET DIAGNOSTICS v_token_rows = ROW_COUNT;

    DELETE FROM auth.permissions_cache WHERE expires_at < p_now;
    GET DIAGNOSTICS v_permission_rows = ROW_COUNT;

    RETURN v_token_rows + v_permission_rows;
END;
$$ LANGUAGE plpgsql;

-- Shared resolvers
CREATE OR REPLACE FUNCTION auth.sp_services_resolve(
    p_name TEXT,
    p_create_if_missing BOOLEAN DEFAULT FALSE
) RETURNS INT AS $$
DECLARE
    v_id INT;
BEGIN
    SELECT id INTO v_id FROM auth.services WHERE name = p_name;
    IF v_id IS NOT NULL THEN
        RETURN v_id;
    END IF;

    IF p_create_if_missing THEN
        INSERT INTO auth.services (name)
        VALUES (p_name)
        ON CONFLICT (name) DO NOTHING
        RETURNING id INTO v_id;

        IF v_id IS NULL THEN
            SELECT id INTO v_id FROM auth.services WHERE name = p_name;
        END IF;
        RETURN v_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_person_resolve_by_username(p_username TEXT)
RETURNS INT AS $$
DECLARE
    v_id INT;
BEGIN
    SELECT id INTO v_id
    FROM auth.person
    WHERE username = p_username
      AND removed_at IS NULL;
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_business_exists(p_id INT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM auth.businesses
        WHERE id = p_id
          AND status = TRUE
          AND removed_at IS NULL
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_user_permissions(
    p_person_id INT,
    p_business_id INT,
    p_service_id INT
) RETURNS TABLE(name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT perm.name FROM (
        SELECT DISTINCT p.id, p.name
        FROM auth.person_service_role psr
        JOIN auth.business_users bu
          ON bu.business_id = psr.business_id
          AND bu.person_id = psr.person_id
          AND bu.status = TRUE
          AND bu.removed_at IS NULL
        JOIN auth.role_permission rp ON rp.role_id = psr.role_id
        JOIN auth.permission p ON p.id = rp.permission_id
        WHERE psr.person_id = p_person_id
          AND psr.business_id = p_business_id
          AND psr.service_id = p_service_id
    ) perm
    ORDER BY perm.id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_user_roles(
    p_person_id INT,
    p_business_id INT,
    p_service_id INT
) RETURNS TABLE(name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.name
    FROM auth.person_service_role psr
    JOIN auth.business_users bu
      ON bu.business_id = psr.business_id
      AND bu.person_id = psr.person_id
      AND bu.status = TRUE
      AND bu.removed_at IS NULL
    JOIN auth.role r ON r.id = psr.role_id
    WHERE psr.person_id = p_person_id
      AND psr.business_id = p_business_id
      AND psr.service_id = p_service_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_permissions_resolve(p_name TEXT)
RETURNS INT AS $$
DECLARE
    v_id INT;
BEGIN
    SELECT id INTO v_id FROM auth.permission WHERE name = p_name;
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_person_can_register_services(p_person_id INT)
RETURNS BOOLEAN AS $$
DECLARE
    v_can_register BOOLEAN;
BEGIN
    SELECT can_register_services INTO v_can_register
    FROM auth.person
    WHERE id = p_person_id
      AND removed_at IS NULL;
    RETURN v_can_register;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_service_is_active(p_service_id INT)
RETURNS BOOLEAN AS $$
DECLARE
    v_status BOOLEAN;
BEGIN
    SELECT status INTO v_status
    FROM auth.services
    WHERE id = p_service_id;
    RETURN v_status;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_service_token_data(p_service_id INT)
RETURNS TABLE(id INT, name TEXT, status BOOLEAN) AS $$
BEGIN
    RETURN QUERY
    SELECT s.id, s.name, s.status
    FROM auth.services s
    WHERE s.id = p_service_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_default_store_service()
RETURNS INT AS $$
DECLARE
    v_id INT;
BEGIN
    SELECT id INTO v_id
    FROM auth.services
    WHERE name IN ('UI Store', 'ui-store')
      AND status = TRUE
    ORDER BY CASE WHEN name = 'UI Store' THEN 0 ELSE 1 END
    LIMIT 1;
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_admin_role_id()
RETURNS INT AS $$
DECLARE
    v_id INT;
BEGIN
    SELECT id INTO v_id FROM auth.role WHERE name = 'Admin';
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

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
    WHERE id = p_id
      AND (
        p_name IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM auth.role r2
            WHERE r2.name = p_name
              AND r2.id <> p_id
        )
      );
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
    WHERE id = p_id
      AND (
        p_name IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM auth.permission p2
            WHERE p2.name = p_name
              AND p2.id <> p_id
        )
      );
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

-- Global role-permission relationships
CREATE OR REPLACE PROCEDURE auth.assign_permission_to_role(
    p_role_id INT,
    p_permission_id INT
) AS $$
BEGIN
    INSERT INTO auth.role_permission (role_id, permission_id)
    VALUES (p_role_id, p_permission_id)
    ON CONFLICT (role_id, permission_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_permission_from_role(
    p_role_id INT,
    p_permission_id INT
) AS $$
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

CREATE OR REPLACE PROCEDURE auth.check_service_role_link(
    p_service_id INT,
    p_role_id INT,
    OUT link_exists BOOLEAN
) AS $$
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM auth.service_roles
        WHERE service_id = p_service_id
          AND role_id = p_role_id
    )
    INTO link_exists;
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

CREATE OR REPLACE FUNCTION auth.default_business_id()
RETURNS INT AS $$
DECLARE
    v_business_id INT;
BEGIN
    SELECT id
    INTO v_business_id
    FROM auth.businesses
    WHERE document_type = 'RUC'
      AND document_number = '00000000001'
      AND status = TRUE
      AND removed_at IS NULL
    LIMIT 1;

    IF v_business_id IS NULL THEN
        SELECT id
        INTO v_business_id
        FROM auth.businesses
        WHERE status = TRUE
          AND removed_at IS NULL
        ORDER BY id
        LIMIT 1;
    END IF;

    IF v_business_id IS NULL THEN
        RAISE EXCEPTION 'default business not found';
    END IF;

    RETURN v_business_id;
END;
$$ LANGUAGE plpgsql;

-- Person assignments to service roles
CREATE OR REPLACE PROCEDURE auth.assign_role_to_person_in_service(p_person_id INT, p_service_id INT, p_role_id INT) AS $$
BEGIN
    CALL auth.assign_role_to_person_in_business_service(
        p_person_id,
        auth.default_business_id(),
        p_service_id,
        p_role_id
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.assign_role_to_person_in_business_service(
    p_person_id INT,
    p_business_id INT,
    p_service_id INT,
    p_role_id INT
) AS $$
BEGIN
    INSERT INTO auth.business_users (business_id, person_id)
    VALUES (p_business_id, p_person_id)
    ON CONFLICT (business_id, person_id) DO NOTHING;

    INSERT INTO auth.person_service_role (business_id, person_id, service_id, role_id)
    VALUES (p_business_id, p_person_id, p_service_id, p_role_id)
    ON CONFLICT (business_id, person_id, service_id, role_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_role_from_person_in_service(p_person_id INT, p_service_id INT, p_role_id INT) AS $$
BEGIN
    CALL auth.remove_role_from_person_in_business_service(
        p_person_id,
        auth.default_business_id(),
        p_service_id,
        p_role_id
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.remove_role_from_person_in_business_service(
    p_person_id INT,
    p_business_id INT,
    p_service_id INT,
    p_role_id INT
) AS $$
BEGIN
    DELETE FROM auth.person_service_role
    WHERE person_id = p_person_id
      AND business_id = p_business_id
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
      AND psr.business_id = auth.default_business_id()
      AND psr.service_id = p_service_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.list_person_roles_in_business_service(
    p_person_id INT,
    p_business_id INT,
    p_service_id INT
)
RETURNS TABLE(id INT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT r.id, r.name
    FROM auth.role r
    JOIN auth.person_service_role psr ON r.id = psr.role_id
    WHERE psr.person_id = p_person_id
      AND psr.business_id = p_business_id
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
      AND psr.business_id = auth.default_business_id()
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
        JOIN auth.role_permission rp ON rp.role_id = psr.role_id
        JOIN auth.permission p ON rp.permission_id = p.id
        WHERE psr.person_id = p_person_id
          AND psr.business_id = auth.default_business_id()
          AND psr.service_id = p_service_id
          AND p.name = p_permission_name
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.check_person_permission_in_business_service(
  p_person_id INT,
  p_business_id INT,
  p_service_id INT,
  p_permission_name TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM auth.person_service_role psr
        JOIN auth.business_users bu
          ON bu.business_id = psr.business_id
          AND bu.person_id = psr.person_id
          AND bu.status = TRUE
          AND bu.removed_at IS NULL
        JOIN auth.role_permission rp ON rp.role_id = psr.role_id
        JOIN auth.permission p ON rp.permission_id = p.id
        WHERE psr.person_id = p_person_id
          AND psr.business_id = p_business_id
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
      AND psr.business_id = auth.default_business_id()
      AND s.status = TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.patch_user_app_settings(
    p_business_id INT,
    p_user_id INT,
    p_app_id TEXT,
    p_settings_patch JSONB
) AS $$
BEGIN
    INSERT INTO auth.user_app_settings (
        business_id,
        user_id,
        app_id,
        settings
    )
    VALUES (
        p_business_id,
        p_user_id,
        p_app_id,
        COALESCE(p_settings_patch, '{}'::jsonb)
    )
    ON CONFLICT (business_id, user_id, app_id)
    DO UPDATE SET
        settings = auth.user_app_settings.settings || COALESCE(EXCLUDED.settings, '{}'::jsonb),
        updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_business_user_exists(p_business_id INT, p_user_id INT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM auth.business_users bu
        JOIN auth.businesses b ON b.id = bu.business_id
        WHERE bu.business_id = p_business_id
          AND bu.person_id = p_user_id
          AND bu.status = TRUE
          AND bu.removed_at IS NULL
          AND b.status = TRUE
          AND b.removed_at IS NULL
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_list_user_businesses(p_user_id INT)
RETURNS TABLE(
    id INT,
    name TEXT,
    legal_name TEXT,
    document_type TEXT,
    document_number TEXT,
    status BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT b.id, b.name, b.legal_name, b.document_type::text, b.document_number, b.status
    FROM auth.businesses b
    JOIN auth.business_users bu ON bu.business_id = b.id
    WHERE bu.person_id = p_user_id
      AND bu.status = TRUE
      AND bu.removed_at IS NULL
      AND b.status = TRUE
      AND b.removed_at IS NULL
    ORDER BY b.name, b.id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_user_app_settings(
    p_business_id INT,
    p_user_id INT,
    p_app_id TEXT
) RETURNS TEXT AS $$
DECLARE
    v_settings TEXT;
BEGIN
    SELECT COALESCE(
        (
            SELECT settings::text
            FROM auth.user_app_settings
            WHERE business_id = p_business_id
              AND user_id = p_user_id
              AND app_id = p_app_id
        ),
        '{}'::text
    )
    INTO v_settings;
    RETURN v_settings;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_login_user(p_username TEXT)
RETURNS TABLE(id INT, username TEXT, password_hash TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.username, p.password_hash, p.name
    FROM auth.person p
    WHERE p.username = p_username
      AND p.removed_at IS NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_latest_valid_user_token(p_user_id TEXT, p_now BIGINT)
RETURNS TABLE(token TEXT, expires_at BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT tc.token, tc.expires_at
    FROM auth.tokens_cache tc
    WHERE tc.payload ->> 'user_id' = p_user_id
      AND tc.expires_at > p_now
    ORDER BY tc.expires_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_get_person_data(p_person_id INT)
RETURNS TABLE(id INT, username TEXT, name TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.username, p.name
    FROM auth.person p
    WHERE p.id = p_person_id
      AND p.removed_at IS NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_business_role_admin_exists(p_person_id INT, p_business_id INT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM auth.person_service_role psr
        JOIN auth.business_users bu
          ON bu.business_id = psr.business_id
          AND bu.person_id = psr.person_id
          AND bu.status = TRUE
          AND bu.removed_at IS NULL
        JOIN auth.role r ON r.id = psr.role_id
        WHERE psr.person_id = p_person_id
          AND psr.business_id = p_business_id
          AND r.name = 'Admin'
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_list_businesses()
RETURNS TABLE(
    id INT,
    name TEXT,
    legal_name TEXT,
    document_type TEXT,
    document_number TEXT,
    status BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT b.id, b.name, b.legal_name, b.document_type::text, b.document_number, b.status
    FROM auth.businesses b
    WHERE b.removed_at IS NULL
    ORDER BY b.id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_create_business(
    p_name TEXT,
    p_legal_name TEXT,
    p_document_type TEXT,
    p_document_number TEXT,
    p_status BOOLEAN
) RETURNS TABLE(
    id INT,
    name TEXT,
    legal_name TEXT,
    document_type TEXT,
    document_number TEXT,
    status BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    INSERT INTO auth.businesses (name, legal_name, document_type, document_number, status)
    VALUES (p_name, p_legal_name, p_document_type::auth.document_type, p_document_number, COALESCE(p_status, TRUE))
    RETURNING auth.businesses.id,
              auth.businesses.name,
              auth.businesses.legal_name,
              auth.businesses.document_type::text,
              auth.businesses.document_number,
              auth.businesses.status;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_create_my_business(
    p_person_id INT,
    p_name TEXT,
    p_legal_name TEXT,
    p_document_type TEXT,
    p_document_number TEXT,
    p_service_id INT,
    p_role_id INT
) RETURNS TABLE(
    id INT,
    name TEXT,
    legal_name TEXT,
    document_type TEXT,
    document_number TEXT,
    status BOOLEAN
) AS $$
DECLARE
    v_business_id INT;
BEGIN
    INSERT INTO auth.businesses (name, legal_name, document_type, document_number, status)
    VALUES (p_name, p_legal_name, p_document_type::auth.document_type, p_document_number, TRUE)
    RETURNING auth.businesses.id INTO v_business_id;

    INSERT INTO auth.business_users (business_id, person_id, status, removed_at)
    VALUES (v_business_id, p_person_id, TRUE, NULL)
    ON CONFLICT (business_id, person_id)
    DO UPDATE SET status = TRUE, removed_at = NULL;

    INSERT INTO auth.service_roles (service_id, role_id)
    VALUES (p_service_id, p_role_id)
    ON CONFLICT (service_id, role_id) DO NOTHING;

    INSERT INTO auth.person_service_role (business_id, person_id, service_id, role_id)
    VALUES (v_business_id, p_person_id, p_service_id, p_role_id)
    ON CONFLICT (business_id, person_id, service_id, role_id) DO NOTHING;

    RETURN QUERY
    SELECT b.id, b.name, b.legal_name, b.document_type::text, b.document_number, b.status
    FROM auth.businesses b
    WHERE b.id = v_business_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_update_business(
    p_id INT,
    p_name TEXT,
    p_legal_name TEXT,
    p_document_type TEXT,
    p_document_number TEXT,
    p_status BOOLEAN
) RETURNS TABLE(
    id INT,
    name TEXT,
    legal_name TEXT,
    document_type TEXT,
    document_number TEXT,
    status BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    UPDATE auth.businesses b
    SET name = p_name,
        legal_name = p_legal_name,
        document_type = p_document_type::auth.document_type,
        document_number = p_document_number,
        status = COALESCE(p_status, b.status)
    WHERE b.id = p_id
      AND b.removed_at IS NULL
    RETURNING b.id, b.name, b.legal_name, b.document_type::text, b.document_number, b.status;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_delete_business(p_id INT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    UPDATE auth.businesses
    SET status = FALSE,
        removed_at = EXTRACT(EPOCH FROM NOW())::BIGINT
    WHERE id = p_id
      AND removed_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_list_business_users(p_business_id INT)
RETURNS TABLE(
    business_id INT,
    person_id INT,
    username TEXT,
    name TEXT,
    status BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT bu.business_id, p.id AS person_id, p.username, p.name, bu.status
    FROM auth.business_users bu
    JOIN auth.person p ON p.id = bu.person_id
    WHERE bu.business_id = p_business_id
      AND bu.removed_at IS NULL
      AND p.removed_at IS NULL
    ORDER BY p.username, p.id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.sp_assign_business_user(p_business_id INT, p_person_id INT) AS $$
BEGIN
    INSERT INTO auth.business_users (business_id, person_id, status, removed_at)
    VALUES (p_business_id, p_person_id, TRUE, NULL)
    ON CONFLICT (business_id, person_id)
    DO UPDATE SET status = TRUE, removed_at = NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_remove_business_user(p_business_id INT, p_person_id INT)
RETURNS BIGINT AS $$
DECLARE
    v_rows BIGINT;
BEGIN
    UPDATE auth.business_users
    SET status = FALSE,
        removed_at = EXTRACT(EPOCH FROM NOW())::BIGINT
    WHERE business_id = p_business_id
      AND person_id = p_person_id
      AND removed_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_create_business_invitation(
    p_code TEXT,
    p_business_id INT,
    p_service_id INT,
    p_role_id INT,
    p_created_by_person_id INT,
    p_expires_at BIGINT
) RETURNS TABLE(
    id INT,
    code TEXT,
    business_id INT,
    service_id INT,
    role_id INT,
    expires_at BIGINT
) AS $$
BEGIN
    RETURN QUERY
    INSERT INTO auth.business_invitations (
        code, business_id, service_id, role_id, created_by_person_id, expires_at
    )
    VALUES (p_code, p_business_id, p_service_id, p_role_id, p_created_by_person_id, p_expires_at)
    RETURNING auth.business_invitations.id,
              auth.business_invitations.code,
              auth.business_invitations.business_id,
              auth.business_invitations.service_id,
              auth.business_invitations.role_id,
              auth.business_invitations.expires_at;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_accept_business_invitation(
    p_code TEXT,
    p_person_id INT,
    p_now BIGINT
) RETURNS TABLE(
    business_id INT,
    service_id INT,
    role_id INT
) AS $$
DECLARE
    v_invitation RECORD;
BEGIN
    SELECT id, bi.business_id, bi.service_id, bi.role_id
    INTO v_invitation
    FROM auth.business_invitations bi
    WHERE bi.code = p_code
      AND bi.used_at IS NULL
      AND bi.removed_at IS NULL
      AND bi.expires_at > p_now;

    IF v_invitation.id IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO auth.business_users (business_id, person_id, status, removed_at)
    VALUES (v_invitation.business_id, p_person_id, TRUE, NULL)
    ON CONFLICT (business_id, person_id)
    DO UPDATE SET status = TRUE, removed_at = NULL;

    INSERT INTO auth.person_service_role (business_id, person_id, service_id, role_id)
    VALUES (v_invitation.business_id, p_person_id, v_invitation.service_id, v_invitation.role_id)
    ON CONFLICT (business_id, person_id, service_id, role_id) DO NOTHING;

    UPDATE auth.business_invitations
    SET used_at = p_now,
        used_by_person_id = p_person_id
    WHERE id = v_invitation.id
      AND used_at IS NULL;

    business_id := v_invitation.business_id;
    service_id := v_invitation.service_id;
    role_id := v_invitation.role_id;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth.sp_direct_role_resolve(
    p_business_id INT,
    p_person_id INT,
    p_service_id INT
) RETURNS INT AS $$
DECLARE
    v_name TEXT := format('direct:%s:%s:%s', p_business_id, p_person_id, p_service_id);
    v_id INT;
BEGIN
    SELECT id INTO v_id FROM auth.role WHERE name = v_name;
    IF v_id IS NOT NULL THEN
        RETURN v_id;
    END IF;

    INSERT INTO auth.role (name)
    VALUES (v_name)
    ON CONFLICT (name) DO NOTHING
    RETURNING id INTO v_id;

    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM auth.role WHERE name = v_name;
    END IF;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE auth.sp_grant_person_permission(
    p_business_id INT,
    p_person_id INT,
    p_service_id INT,
    p_role_id INT,
    p_permission_id INT
) AS $$
BEGIN
    INSERT INTO auth.service_roles (service_id, role_id)
    VALUES (p_service_id, p_role_id)
    ON CONFLICT (service_id, role_id) DO NOTHING;

    INSERT INTO auth.role_permission (role_id, permission_id)
    VALUES (p_role_id, p_permission_id)
    ON CONFLICT (role_id, permission_id) DO NOTHING;

    INSERT INTO auth.business_users (business_id, person_id)
    VALUES (p_business_id, p_person_id)
    ON CONFLICT (business_id, person_id) DO NOTHING;

    INSERT INTO auth.person_service_role (business_id, person_id, service_id, role_id)
    VALUES (p_business_id, p_person_id, p_service_id, p_role_id)
    ON CONFLICT (business_id, person_id, service_id, role_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;
