#!/usr/bin/env bash
# Genera generated/credential_config.sql (UPSERT idempotente de credential_config) y
# generated/credencial-muestra.json (la credencial que saldría de la plantilla, con valores
# ficticios). Toda la lógica está en scripts/lib/credencial.mjs; aquí solo se prepara el entorno.
#
# Qué hace el SQL, y por qué (R2, R3, R7; D6):
#   - tipos y contextos se guardan ordenados como Collections.sort de Java (Certify ordena antes
#     de buscar la configuración; sin ordenar, «CredentialConfig not found» al emitir);
#   - el @context incluye credentials/v2, el contexto propio (scripts/generate-context.mjs) y la
#     suite Ed25519-2020, y la plantilla es VC 2.0 (validFrom/validUntil);
#   - config_id = CREDENTIAL_CONFIG_KEY_ID (determinista) y ON CONFLICT … DO UPDATE conserva
#     `status`, así que se puede volver a aplicar con scripts/apply-credential.sh sin recrear Postgres.

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
run_node generate-credential.mjs generated
