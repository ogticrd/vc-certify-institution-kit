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
export_env_for_templates

OUT_FILE="${GENERATED_DIR}/caddy/Caddyfile"
mkdir -p "$(dirname "${OUT_FILE}")"

[[ -n "${CADDY_ACME_EMAIL:-}" ]] || { echo "ERROR: CADDY_ACME_EMAIL requerido (Let's Encrypt / ACME)" >&2; exit 1; }

case "${TLS_MODE}" in
  domain)
    render_template \
      "${KIT_DIR}/templates/Caddyfile.domain.tpl" \
      "${OUT_FILE}" \
      '$CERTIFY_PUBLIC_HOST $CADDY_ACME_EMAIL'
    ;;
  ip)
    render_template \
      "${KIT_DIR}/templates/Caddyfile.ip.tpl" \
      "${OUT_FILE}" \
      '$IP_HOSTNAME $CADDY_ACME_EMAIL'
    ;;
  *)
    echo "ERROR: TLS_MODE inválido: ${TLS_MODE}" >&2
    exit 1
    ;;
esac

echo "Caddyfile generado en ${OUT_FILE}"
