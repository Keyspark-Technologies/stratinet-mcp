#!/bin/sh
set -eu

gunzip -cf /corpus/dump \
  | grep -vE '^\\(un)?restrict |^SET transaction_timeout' \
  | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE mcp_reader LOGIN PASSWORD 'mcp_reader';
GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO mcp_reader;
GRANT USAGE ON SCHEMA kb TO mcp_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA kb TO mcp_reader;
SQL
