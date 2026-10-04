#!/usr/bin/env bash
# Genera generated/contextos/<CREDENTIAL_CONFIG_KEY_ID>.json, el contexto JSON-LD propio que define
# cada atributo de CREDENTIAL_ATTRIBUTES (R1). Sin Node local usa `docker run node:22-alpine`.

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
run_node generate-context.mjs generated
