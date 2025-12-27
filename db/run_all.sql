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

\echo 'Loading demo data...'
\ir demo_data.sql

\echo 'Database setup completed successfully.'
