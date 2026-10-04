#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/render.sh
source "${SCRIPT_DIR}/lib/render.sh"

load_env
apply_defaults
derive_public_url
derive_did_url
validate_env
export_env_for_templates

OUT_DIR="${GENERATED_DIR}/config"
ensure_generated_dir
mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

VARS='$CERTIFY_PUBLIC_URL $DID_URL $INSTITUTION_DISPLAY_NAME $POSTGRES_DB $POSTGRES_USER $AUTH_ISSUER_URL'

render_template \
  "${KIT_DIR}/templates/certify-default.properties.tpl" \
  "${OUT_DIR}/certify-default.properties" \
  "${VARS}"

INST_VARS='$RESTAPI_BASE_URL $RESTAPI_SCOPE_ENDPOINT_MAPPING $RESTAPI_TOKEN_URL $OAUTH_CLIENT_ID $POSTGRES_DB'
render_template \
  "${KIT_DIR}/templates/certify-institution.properties.tpl" \
  "${OUT_DIR}/certify-institution.properties" \
  "${INST_VARS}"

# MODO 644 A PROPÓSITO (K1). Certify corre dentro del contenedor como el usuario mosip (uid 1001, ver el
# Dockerfile) y lee estos ficheros por bind mount con el modo del host: un 600 del usuario que instala
# (otro uid, p. ej. 1000) los dejaría ilegibles en Linux y Certify no arrancaría; un 640 exigiría un chgrp a
# un gid que el instalador no puede asignar sin root. Por eso estos ficheros NO llevan ningún secreto: la
# contraseña de Postgres, la del keystore y el secreto OAuth son marcadores (${KIT_DB_PASSWORD}…) que Spring
# resuelve desde el entorno del contenedor, que docker compose llena desde generated/.env.runtime (600). El
# directorio generated/ (700) impide además que otros usuarios del servidor lleguen hasta aquí.
chmod 644 "${OUT_DIR}/certify-default.properties" "${OUT_DIR}/certify-institution.properties"

echo "Properties generadas en ${OUT_DIR}"
