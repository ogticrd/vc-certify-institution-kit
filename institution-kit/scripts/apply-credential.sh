#!/usr/bin/env bash
# Aplica generated/credential_config.sql a la base de datos en marcha (R7). Úsese tras cambiar
# atributos, etiquetas, display o contexto en el .env: regenera y aplica, sin recrear Postgres
# ni perder el `status` de la credencial.
#
#   ./scripts/apply-credential.sh              regenera (generate-config.sh) y aplica
#   NO_REGENERAR=1 ./scripts/apply-credential.sh   aplica el SQL ya generado
#   DRY_RUN=1 ./scripts/apply-credential.sh        regenera (salvo generated/contextos/, que NO se toca: solo se
#                                                  comprueba) e imprime los comandos de psql y de reinicio sin ejecutarlos
#
# El contexto propio es INMUTABLE (K5, «contexto nuevo = clave nueva»): si cambia la lista de atributos con la
# misma CREDENTIAL_CONFIG_KEY_ID, generate-context.mjs se niega a sobrescribir lo publicado (las credenciales ya
# emitidas dejarían de verificar). Cambie la clave (y ponga la vieja en `inactive`) o, a sabiendas,
# KIT_FORZAR_CONTEXTO=1. Después de aplicar el SQL se reinicia SOLO Certify: guarda la configuración de la
# credencial en caché (3600 s) y seguiría emitiendo con la plantilla vieja.

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
  # En DRY_RUN no se publica nada: generated/contextos/ se comprueba (¿habría que sobrescribir algo?) pero no se escribe.
  if [[ -n "${DRY_RUN:-}" ]]; then export KIT_CONTEXTO_SOLO_COMPROBAR=1; fi
  "${SCRIPT_DIR}/generate-config.sh"
fi

SQL_FILE="${GENERATED_DIR}/credential_config.sql"
[[ -f "${SQL_FILE}" ]] || { echo "ERROR: no existe ${SQL_FILE}; ejecute scripts/generate-config.sh primero." >&2; exit 1; }

cd "${KIT_DIR}"
load_compose_args
PSQL=("${KIT_COMPOSE[@]}" exec -T database psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}")

RESTART=("${KIT_COMPOSE[@]}" restart certify)

if [[ -n "${DRY_RUN:-}" ]]; then
  printf '%q ' "${PSQL[@]}"; printf '< %q\n' "${SQL_FILE}"
  # Después de aplicar, Certify se reinicia (solo él: ni la base ni Caddy).
  KIT_DRY_RUN=1 _ejecutar_o_mostrar "${RESTART[@]}"
  exit 0
fi

echo "=== Aplicando la credencial ${CREDENTIAL_CONFIG_KEY_ID} ==="
"${PSQL[@]}" < "${SQL_FILE}"

# La fila resultante, sin la plantilla en base64 (ocupa cientos de caracteres).
echo "=== Fila resultante ==="
# Por la entrada estándar y no con -c: así psql sustituye :'clave' (con las comillas bien puestas).
printf '%s\n' "SELECT credential_config_key_id, config_id, status, credential_type, context, credential_format, did_url, signature_crypto_suite, scope, display_order, upd_dtimes FROM certify.credential_config WHERE credential_config_key_id = :'clave';" \
  | "${PSQL[@]}" -x -v "clave=${CREDENTIAL_CONFIG_KEY_ID}"

# Certify guarda credentialConfig y la plantilla en caché (spring.cache, 3600 s): sin reiniciarlo seguiría
# emitiendo con la configuración vieja contra la base nueva. Solo Certify; la base y Caddy siguen en pie.
echo "=== Reiniciando Certify (guarda la configuración de la credencial en caché) ==="
"${RESTART[@]}"
echo "Listo. Compruebe con ./scripts/verify-install.sh cuando Certify vuelva a estar UP."
