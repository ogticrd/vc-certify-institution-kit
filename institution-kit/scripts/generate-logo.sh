#!/usr/bin/env bash
# Copia el logo de la institución (LOGO_PATH, un PNG) a generated/logos/<CREDENTIAL_CONFIG_KEY_ID>.png,
# que Caddy sirve en <CERTIFY_PUBLIC_URL>/logos/<clave>.png (R10). El bloque `display.logo.url` del SQL
# apunta ahí (scripts/lib/credencial.mjs). Ya no hay logo de terceros por defecto.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
validate_logo_path   # define LOGO_PATH_RESOLVED; sale con un error claro si falta o no es PNG

[[ "${CREDENTIAL_CONFIG_KEY_ID:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] \
  || { echo "ERROR: CREDENTIAL_CONFIG_KEY_ID inválido (solo letras, dígitos, «_» y «-»): es el nombre del fichero del logo." >&2; exit 1; }

DESTINO="${GENERATED_DIR}/logos"
mkdir -p "${DESTINO}"
# Un logo viejo de otra clave no se sirve: solo hay un PNG por clave y se reescribe cada vez.
cp "${LOGO_PATH_RESOLVED}" "${DESTINO}/${CREDENTIAL_CONFIG_KEY_ID}.png"
chmod 644 "${DESTINO}/${CREDENTIAL_CONFIG_KEY_ID}.png"
echo "Logo copiado a ${DESTINO}/${CREDENTIAL_CONFIG_KEY_ID}.png"
echo "  URL pública: ${CERTIFY_PUBLIC_URL}/logos/${CREDENTIAL_CONFIG_KEY_ID}.png"
