#!/usr/bin/env bash
# Validate every analyzers/*/*.json flavor definition.
# Run from the repository root. Used by the tests (PR gate) and build workflows,
# and runnable locally: utils/validate-analyzers.sh [registry-owner]
# The owner defaults to citadeliscybersecurity; images must live under ghcr.io/<owner>/.
set -euo pipefail
shopt -s nullglob

OWNER=$(echo "${1:-citadeliscybersecurity}" | tr '[:upper:]' '[:lower:]')
REQUIRED_FIELDS='["name", "version", "author", "url", "license", "description", "dataTypeList", "command", "baseConfig"]'
CONFIG_ITEM_FIELDS='["name", "description", "type", "multi", "required"]'
ALLOWED_REGISTRY="ghcr.io/${OWNER}/"

errors=0
for file in analyzers/*/*.json; do
  missing=$(jq -r --argjson required "$REQUIRED_FIELDS" '
    $required - keys | if length > 0 then @json else empty end
  ' "$file")
  if [ -n "$missing" ]; then
    echo "::error file=$file::Missing required fields: $missing"
    ((errors++)) || true
  fi

  # Name is used in image names and paths: no whitespace, separators or traversal.
  name_invalid=$(jq -r '
    if .name then
      if (.name | test("\\s")) then "name contains whitespace"
      elif (.name | test("[/\\\\]")) then "name contains path separators"
      elif (.name | test("\\.\\.")) then "name contains path traversal (..)"
      else empty end
    else empty end
  ' "$file")
  if [ -n "$name_invalid" ]; then
    echo "::error file=$file::$name_invalid"
    ((errors++)) || true
  fi

  dtype_invalid=$(jq -r 'if .dataTypeList and (.dataTypeList | type) != "array" then "dataTypeList must be array" else empty end' "$file")
  if [ -n "$dtype_invalid" ]; then
    echo "::error file=$file::$dtype_invalid"
    ((errors++)) || true
  fi

  rogue=$(jq -r --arg allowed "$ALLOWED_REGISTRY" '
    if .dockerImage and (.dockerImage | startswith($allowed) | not) then .dockerImage else empty end
  ' "$file")
  if [ -n "$rogue" ]; then
    echo "::error file=$file::dockerImage $rogue must start with $ALLOWED_REGISTRY (or be omitted)"
    ((errors++)) || true
  fi

  # Incomplete configurationItems are warnings only.
  jq -r --argjson required "$CONFIG_ITEM_FIELDS" '
    .configurationItems // [] | to_entries[] |
    ($required - (.value | keys)) as $missing |
    if ($missing | length) > 0 then "configurationItems[\(.key)]: missing \($missing | @json)" else empty end
  ' "$file" | while read -r line; do
    echo "::warning file=$file::$line"
  done
done

if [ "$errors" -gt 0 ]; then
  echo "::error::Validation failed with $errors error(s)"
  exit 1
fi
echo "All definitions valid"
