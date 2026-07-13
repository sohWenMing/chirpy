#!/usr/bin/bash

set -euo pipefail
PG_STRING="postgres://postgres:password@localhost:5432/chirpy"
cd ./sql/schema && goose postgres ${PG_STRING} up
