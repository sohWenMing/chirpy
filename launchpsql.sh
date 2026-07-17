#!/usr/bin/bash
set -euo pipefail 

echo "starting psql"
psql -h localhost -U postgres -d chirpy -p 5432
