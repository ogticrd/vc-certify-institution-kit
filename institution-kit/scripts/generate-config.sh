#!/usr/bin/env bash
# Genera todo lo que el kit necesita en generated/ a partir del .env.
#
# SECRETOS (R9, D7): aquí se escribe generated/.env.runtime (modo 600) y, si POSTGRES_PASSWORD o la
# contraseña del keystore (KEYSTORE_PASSWORD) valen el defecto (postgres / local) o están vacías, se
# generan con `openssl rand -hex 32` y se guardan SOLO en ese fichero. Este script no imprime ninguna
# contraseña ni el OAUTH_CLIENT_SECRET. La generación es para INSTALACIONES NUEVAS: la contraseña de
# Postgres queda en el volumen de datos y la del keystore en el keystore de Certify; si ya existen,
# cambiarla aquí rompe el arranque. En una instalación existente la institución fija
# POSTGRES_PASSWORD (y KEYSTORE_PASSWORD) explícitamente con el valor que ya tiene la base (o
# KIT_CONSERVAR_SECRETOS_POR_DEFECTO=1 para no generar). Las ya generadas se reutilizan en cada
# ejecución (se leen de .env.runtime).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PARENT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

echo "=== Generando configuración del kit ==="

# Se valida todo primero (el logo incluido: sin LOGO_PATH válido no tiene sentido generar el resto) y
# se resuelven los secretos antes de que los demás generadores los lean.
load_env
apply_defaults
derive_public_url
derive_did_url
validate_env
write_runtime_env
write_compose_args
echo "  -> ${RUNTIME_ENV} (modo 600; contraseñas de base de datos y keystore)"
echo "  -> ${GENERATED_DIR}/compose-args (orden de docker compose para TLS_MODE=${TLS_MODE})"

"${SCRIPT_DIR}/generate-logo.sh"
"${SCRIPT_DIR}/generate-properties.sh"
"${SCRIPT_DIR}/generate-caddy.sh"
"${SCRIPT_DIR}/generate-context.sh"
"${SCRIPT_DIR}/generate-credential-sql.sh"
# La carpeta del DID corregido tiene que existir aunque esté vacía: docker compose la monta en Caddy
# (si no existiera, Docker la crearía como root). generate-did.sh la rellena cuando Certify está UP.
mkdir -p "${SCRIPT_PARENT}/generated/did"
echo "=== Configuración generada en generated/ ==="
