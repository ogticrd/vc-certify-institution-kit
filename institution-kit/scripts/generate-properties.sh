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
mkdir -p "${OUT_DIR}"

VARS='$CERTIFY_PUBLIC_URL $DID_URL $INSTITUTION_DISPLAY_NAME $POSTGRES_DB $POSTGRES_USER $POSTGRES_PASSWORD'

render_template \
  "${KIT_DIR}/templates/certify-default.properties.tpl" \
  "${OUT_DIR}/certify-default.properties" \
  "${VARS}"

INST_VARS='$RESTAPI_BASE_URL $RESTAPI_SCOPE_ENDPOINT_MAPPING $OAUTH_CLIENT_ID $OAUTH_CLIENT_SECRET $POSTGRES_DB'
render_template \
  "${KIT_DIR}/templates/certify-institution.properties.tpl" \
  "${OUT_DIR}/certify-institution.properties" \
  "${INST_VARS}"

echo "Properties generadas en ${OUT_DIR}"
