#!/usr/bin/env bash
# Aplica generated/credential_config.sql a la base de datos en marcha (R7). Úsese tras cambiar
# atributos, etiquetas, display o contexto en el .env: regenera y aplica, sin recrear Postgres
# ni perder el `status` de la credencial.
#
#   ./scripts/apply-credential.sh              regenera (generate-config.sh) y aplica
#   NO_REGENERAR=1 ./scripts/apply-credential.sh   aplica el SQL ya generado
#   DRY_RUN=1 ./scripts/apply-credential.sh        regenera (solo ficheros locales) e imprime el comando de psql sin ejecutarlo
#
# El contexto propio no se edita una vez publicado: si cambia la lista de atributos, las credenciales
# ya emitidas dejan de verificar con el contexto nuevo (ver la guía). Aquí solo se aplica.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
derive_did_url
validate_env

if [[ -z "${NO_REGENERAR:-}" ]]; then
  "${SCRIPT_DIR}/generate-config.sh"
fi

SQL_FILE="${GENERATED_DIR}/credential_config.sql"
[[ -f "${SQL_FILE}" ]] || { echo "ERROR: no existe ${SQL_FILE}; ejecute scripts/generate-config.sh primero." >&2; exit 1; }

cd "${KIT_DIR}"
load_compose_args
PSQL=("${KIT_COMPOSE[@]}" exec -T database psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}")

if [[ -n "${DRY_RUN:-}" ]]; then
  printf '%q ' "${PSQL[@]}"; printf '< %q\n' "${SQL_FILE}"
  exit 0
fi

echo "=== Aplicando la credencial ${CREDENTIAL_CONFIG_KEY_ID} ==="
"${PSQL[@]}" < "${SQL_FILE}"

# La fila resultante, sin la plantilla en base64 (ocupa cientos de caracteres).
echo "=== Fila resultante ==="
# Por la entrada estándar y no con -c: así psql sustituye :'clave' (con las comillas bien puestas).
printf '%s\n' "SELECT credential_config_key_id, config_id, status, credential_type, context, credential_format, did_url, signature_crypto_suite, scope, display_order, upd_dtimes FROM certify.credential_config WHERE credential_config_key_id = :'clave';" \
  | "${PSQL[@]}" -x -v "clave=${CREDENTIAL_CONFIG_KEY_ID}"
