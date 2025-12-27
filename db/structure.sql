-- Main Schema for the Authentication and Authorization API

-- Role and permissions for local development/tests.
DO
$$
BEGIN
	IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin') THEN
		CREATE ROLE admin LOGIN PASSWORD 'admin';
	ELSE
		ALTER ROLE admin WITH LOGIN PASSWORD 'admin';
	END IF;
END;
$$;

GRANT ALL PRIVILEGES ON DATABASE api_auth TO admin;

-- Schema
CREATE SCHEMA IF NOT EXISTS auth;

-- Custom Types
CREATE TYPE auth.document_type AS ENUM ('DNI', 'CE', 'RUC');
CREATE TYPE auth.person_type AS ENUM ('N', 'J');

-- Tables
CREATE TABLE auth.person (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  person_type auth.person_type NOT NULL DEFAULT 'N',
  document_type auth.document_type NOT NULL DEFAULT 'DNI',
  document_number TEXT NOT NULL,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  removed_at BIGINT,
  UNIQUE (document_type, document_number)
);

CREATE TABLE auth.role (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);

CREATE TABLE auth.permission (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);

CREATE TABLE auth.services (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  status BOOLEAN NOT NULL DEFAULT TRUE
);

-- Linking Tables

-- Service-Roles (as required by API)
CREATE TABLE auth.service_roles (
  id SERIAL PRIMARY KEY,
  service_id INTEGER REFERENCES auth.services(id) ON DELETE CASCADE NOT NULL,
  role_id INTEGER REFERENCES auth.role(id) ON DELETE CASCADE NOT NULL,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  UNIQUE (service_id, role_id)
);

-- Global role-permission relations
CREATE TABLE auth.role_permission (
  id SERIAL PRIMARY KEY,
  role_id INTEGER REFERENCES auth.role(id) ON DELETE CASCADE NOT NULL,
  permission_id INTEGER REFERENCES auth.permission(id) ON DELETE CASCADE NOT NULL,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  UNIQUE (role_id, permission_id)
);

-- Person-Service-Roles (as required by API, replaces user's person_role)
CREATE TABLE auth.person_service_role (
  id SERIAL PRIMARY KEY,
  person_id INTEGER REFERENCES auth.person(id) ON DELETE CASCADE NOT NULL,
  service_id INTEGER REFERENCES auth.services(id) ON DELETE CASCADE NOT NULL,
  role_id INTEGER REFERENCES auth.role(id) ON DELETE CASCADE NOT NULL,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  UNIQUE (person_id, service_id, role_id)
);

CREATE TABLE auth.tokens_cache (
  token TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  modified_at BIGINT NOT NULL,
  created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
  updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
);

CREATE INDEX idx_auth_tokens_modified_at ON auth.tokens_cache(modified_at);

CREATE OR REPLACE FUNCTION auth.set_epoch_audit_fields()
RETURNS TRIGGER AS $$
DECLARE
  current_epoch BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.created_at IS NULL THEN
      NEW.created_at := current_epoch;
    END IF;
    IF NEW.updated_at IS NULL THEN
      NEW.updated_at := NEW.created_at;
    END IF;
  ELSE
    IF NEW.created_at IS NULL THEN
      NEW.created_at := current_epoch;
    END IF;
    NEW.updated_at := current_epoch;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auth_person_audit
BEFORE INSERT OR UPDATE ON auth.person
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_role_audit
BEFORE INSERT OR UPDATE ON auth.role
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_permission_audit
BEFORE INSERT OR UPDATE ON auth.permission
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_services_audit
BEFORE INSERT OR UPDATE ON auth.services
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_service_roles_audit
BEFORE INSERT OR UPDATE ON auth.service_roles
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_role_permission_audit
BEFORE INSERT OR UPDATE ON auth.role_permission
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_person_service_role_audit
BEFORE INSERT OR UPDATE ON auth.person_service_role
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

CREATE TRIGGER trg_auth_tokens_cache_audit
BEFORE INSERT OR UPDATE ON auth.tokens_cache
FOR EACH ROW
EXECUTE FUNCTION auth.set_epoch_audit_fields();

GRANT USAGE ON SCHEMA auth TO admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO admin;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA auth TO admin;
