#!/usr/bin/env bash
# Genera todo lo que el kit necesita en generated/ a partir del .env.
#
# SECRETOS (R9, D7; K2, K3): aquí se escribe generated/.env.runtime (modo 600) y, si POSTGRES_PASSWORD o la
# contraseña del keystore (KEYSTORE_PASSWORD) valen el defecto (postgres / local) o están vacías, se
# generan con `openssl rand -hex 32` y se guardan SOLO en ese fichero. Este script no imprime ninguna
# contraseña ni el OAUTH_CLIENT_SECRET. Solo se generan en una INSTALACIÓN NUEVA: la contraseña de
# Postgres queda en el volumen de datos y la del keystore en el keystore de Certify. Con una instalación
# previa (generated/.env.runtime, o un contenedor/volumen de este kit) las ya generadas se reutilizan, y si
# siguen siendo las de defecto el kit se detiene y explica cómo rotarlas a mano (scripts/lib/common.sh,
# resolve_secrets). Se resuelven después de validar el .env.

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
ensure_generated_dir
mkdir -p "${SCRIPT_PARENT}/generated/did"
echo "=== Configuración generada en generated/ ==="
