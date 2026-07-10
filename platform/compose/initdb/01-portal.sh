#!/bin/sh
# Runs once on first postgres boot: create the portal database and apply its
# schema (idp migrates itself; portal expects schema.sql pre-applied).
set -eu
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c 'CREATE DATABASE portal OWNER meridian'
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d portal -f /initdb-portal-schema.sql
