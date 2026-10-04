#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PARENT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Generando configuración del kit ==="
# El logo se valida primero: sin LOGO_PATH válido no tiene sentido generar el resto.
"${SCRIPT_DIR}/generate-logo.sh"
"${SCRIPT_DIR}/generate-properties.sh"
"${SCRIPT_DIR}/generate-caddy.sh"
"${SCRIPT_DIR}/generate-context.sh"
"${SCRIPT_DIR}/generate-credential-sql.sh"
# La carpeta del DID corregido tiene que existir aunque esté vacía: docker compose la monta en Caddy
# (si no existiera, Docker la crearía como root). generate-did.sh la rellena cuando Certify está UP.
mkdir -p "${SCRIPT_PARENT}/generated/did"
echo "=== Configuración generada en generated/ ==="
