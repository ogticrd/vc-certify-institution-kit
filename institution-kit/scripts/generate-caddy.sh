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

# Las rutas comunes a todos los modos (actuator, did.json, contextos, logos, certify) están en UN
# fragmento, templates/Caddyfile.comun.inc; las plantillas de modo lo reciben en $CADDY_FRAGMENTO_COMUN
# (envsubst no vuelve a expandir lo sustituido) y lo importan con `import certify_comun`.
CADDY_FRAGMENTO_COMUN="$(cat "${KIT_DIR}/templates/Caddyfile.comun.inc")"
export CADDY_FRAGMENTO_COMUN

OUT_FILE="${GENERATED_DIR}/caddy/Caddyfile"
mkdir -p "$(dirname "${OUT_FILE}")"

# El correo de ACME solo hace falta cuando Caddy pide certificados (domain, ip); en proxy no hay ACME.
if [[ "${TLS_MODE}" != "proxy" && -z "${CADDY_ACME_EMAIL:-}" ]]; then
  echo "ERROR: CADDY_ACME_EMAIL requerido (Let's Encrypt / ACME)" >&2
  exit 1
fi

case "${TLS_MODE}" in
  domain)
    render_template \
      "${KIT_DIR}/templates/Caddyfile.domain.tpl" \
      "${OUT_FILE}" \
      '$CERTIFY_PUBLIC_HOST $CADDY_ACME_EMAIL $CADDY_FRAGMENTO_COMUN'
    ;;
  ip)
    render_template \
      "${KIT_DIR}/templates/Caddyfile.ip.tpl" \
      "${OUT_FILE}" \
      '$IP_HOSTNAME $CADDY_ACME_EMAIL $CADDY_FRAGMENTO_COMUN'
    ;;
  proxy)
    render_template \
      "${KIT_DIR}/templates/Caddyfile.proxy.tpl" \
      "${OUT_FILE}" \
      '$TRUSTED_PROXIES $CADDY_FRAGMENTO_COMUN'
    ;;
  *)
    echo "ERROR: TLS_MODE inválido: ${TLS_MODE}" >&2
    exit 1
    ;;
esac

echo "Caddyfile generado en ${OUT_FILE}"
