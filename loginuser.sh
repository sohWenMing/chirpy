#!/usr/bin/bash
set -euo pipefail
echo "Total args passed: ${#}"
if [[ "${#}" -eq 2 ]]; then
    echo "correct - 2 arguments passed"
    echo "arg 0: ${0}"
    echo "arg 1: ${1}"
    echo "arg 2: ${2}"
else
    echo "wrong number of arguments passed"
    exit 1
fi

curl -X POST \
-d "{\"password\":\"${1}\",\"email\":\"${2}\"}" \
-H 'Content-Type: application/json' \
http://localhost:8080/api/login
