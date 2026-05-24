\echo 'Connecting to postgres database...'
\c postgres;

\echo 'api_auth...'
DROP DATABASE IF EXISTS api_auth;
CREATE DATABASE api_auth;

\echo 'Switching connection to api_auth...'
\c api_auth;

\echo 'Loading database structure...'
\ir structure.sql

\echo 'Loading stored procedures...'
\ir procedures.sql

\getenv AUTH_DATABASE_URL AUTH_DATABASE_URL
\if :{?AUTH_DATABASE_URL}
\else
\echo 'AUTH_DATABASE_URL is not set. Run with: sudo --preserve-env=AUTH_DATABASE_URL -u postgres psql -f db/run_all.sql'
\quit
\endif

SELECT
  split_part(split_part(:'AUTH_DATABASE_URL', '://', 2), ':', 1) AS db_user,
  split_part(
    split_part(split_part(:'AUTH_DATABASE_URL', '://', 2), '@', 1),
    ':',
    2
  ) AS db_pass
\gset

\echo 'Applying auth schema permissions...'
ALTER ROLE :"db_user" WITH PASSWORD :'db_pass';
GRANT USAGE ON SCHEMA auth TO :"db_user";
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO :"db_user";
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA auth TO :"db_user";
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth TO :"db_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO :"db_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT USAGE,SELECT ON SEQUENCES TO :"db_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT EXECUTE ON FUNCTIONS TO :"db_user";

\echo 'Loading demo data...'
\ir demo_data.sql

\echo 'Loading authorization seed...'
\ir authorization_seed.sql

\echo 'Database setup completed successfully.'
