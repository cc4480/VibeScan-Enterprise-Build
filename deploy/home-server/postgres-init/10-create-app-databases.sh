#!/bin/sh
# Runs once, when the db container starts with an empty data volume: one login
# role and one database per app, each owned by its role, so an app can only
# reach its own data. Passwords come from the db service's environment (.env).
#
# Passwords go through psql variables (:'pw'), never into the SQL text, so a
# quote in a password cannot break or alter the statement.
#
# `set -e` only, not -u: if the file loses its executable bit (a Windows
# checkout can), the postgres entrypoint sources it instead of running it, and
# -u would then leak into the entrypoint's own shell.
set -e

create_app_db() {
  name="$1"
  password="$2"
  if [ -z "$password" ]; then
    echo "no password set for $name (see .env)" >&2
    exit 1
  fi
  psql -v ON_ERROR_STOP=1 -v name="$name" -v pw="$password" \
    --username "$POSTGRES_USER" --dbname postgres <<'SQL'
CREATE ROLE :"name" LOGIN PASSWORD :'pw';
CREATE DATABASE :"name" OWNER :"name";
REVOKE ALL ON DATABASE :"name" FROM PUBLIC;
SQL
  echo "created database and role: $name"
}

create_app_db secscan "$SECSCAN_DB_PASSWORD"
create_app_db seclayer "$SECLAYER_DB_PASSWORD"
create_app_db complyscan "$COMPLYSCAN_DB_PASSWORD"
create_app_db seoscan "$SEOSCAN_DB_PASSWORD"
