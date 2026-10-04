#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Generando configuración del kit ==="
"${SCRIPT_DIR}/generate-properties.sh"
"${SCRIPT_DIR}/generate-caddy.sh"
"${SCRIPT_DIR}/generate-credential-sql.sh"
echo "=== Configuración generada en generated/ ==="
