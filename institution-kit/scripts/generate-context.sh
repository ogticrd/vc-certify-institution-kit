#!/usr/bin/env bash
# Genera generated/contextos/<CREDENTIAL_CONFIG_KEY_ID>.json (+ .sha256), el contexto JSON-LD propio que
# define cada atributo de CREDENTIAL_ATTRIBUTES (R1). Sin Node local usa `docker run node:22-alpine`.
# El contexto publicado es INMUTABLE (K5): si ya existe uno con otro contenido, falla («contexto nuevo =
# clave nueva»), salvo KIT_FORZAR_CONTEXTO=1. Con KIT_CONTEXTO_SOLO_COMPROBAR=1 no escribe nada (DRY_RUN).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

load_env
apply_defaults
derive_public_url
derive_did_url
export_env_for_templates

ensure_generated_dir
if [[ -n "${KIT_CONTEXTO_SOLO_COMPROBAR:-}" ]]; then
  run_node generate-context.mjs generated --comprobar
else
  run_node generate-context.mjs generated
fi
