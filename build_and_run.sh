#!/usr/bin/bash
set -euo pipefail
go build .
docker build -t nindgabeet/chirpy:latest .
docker compose up
