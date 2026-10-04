#!/usr/bin/env bash
# Render a template with envsubst (only listed variables).

set -euo pipefail

render_template() {
  local template_file="$1"
  local output_file="$2"
  shift 2
  local vars="$1"
  mkdir -p "$(dirname "${output_file}")"
  envsubst "${vars}" < "${template_file}" > "${output_file}"
  echo "  -> ${output_file}"
}
