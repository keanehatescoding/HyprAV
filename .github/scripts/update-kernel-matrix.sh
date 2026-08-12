#!/usr/bin/env bash
# update-kernel-matrix.sh - fetches kernel.org's release list and rewrites
# the kernel_version block in build-matrix.yml between its BEGIN/END
# markers with:
#   - the 2 most recently released non-EOL "longterm" (LTS) branches
#   - the current "stable" release
#
# This deliberately does NOT hardcode branch numbers (6.12, 6.18, ...) -
# it re-derives "the current 2 active LTS branches" from kernel.org's own
# EOL flag every run, so it keeps working unchanged once those branches
# are eventually retired and different ones take their place. See
# https://www.kernel.org/releases.json for the source data and
# https://www.kernel.org/releases.html for what "longterm"/"stable" mean.
#
# Run from the repo root. Exits 0 with no changes if the matrix already
# matches kernel.org's current releases; exits non-zero on any fetch/
# parse failure so the calling workflow doesn't silently open a bad PR.
set -euo pipefail

WORKFLOW_FILE="${1:-.github/workflows/build-matrix.yml}"
RELEASES_URL="https://www.kernel.org/releases.json"
BEGIN_MARKER="          # BEGIN kernel_version"
END_MARKER="          # END kernel_version"

if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "::error::$WORKFLOW_FILE not found" >&2
  exit 1
fi

releases_json="$(curl -fsSL "$RELEASES_URL")"

current_stable="$(
  echo "$releases_json" \
    | jq -r '[.releases[] | select(.moniker=="stable")] | .[0].version // empty'
)"

# kernel.org's releases.json already lists exactly one entry PER active
# branch (each the latest patch release for that branch) - so no need to
# dedupe by major.minor here, just filter to non-EOL longterm entries and
# take the 2 with the highest version. `sort -V` (version sort) handles
# X.Y.Z ordering correctly, unlike a plain lexicographic sort.
mapfile -t lts_versions < <(
  echo "$releases_json" \
    | jq -r '.releases[] | select(.moniker=="longterm" and .iseol==false) | .version' \
    | sort -V \
    | tail -n 2
)

if [ -z "$current_stable" ]; then
  echo "::error::could not find a moniker==\"stable\" entry in $RELEASES_URL" >&2
  exit 1
fi
if [ "${#lts_versions[@]}" -lt 2 ]; then
  echo "::error::expected 2 non-EOL longterm releases, found ${#lts_versions[@]} in $RELEASES_URL" >&2
  exit 1
fi

new_block=$(cat <<EOF
$BEGIN_MARKER
          - "${lts_versions[0]}"  # LTS
          - "${lts_versions[1]}"  # LTS
          - "${current_stable}"  # current stable
$END_MARKER
EOF
)

if ! grep -qF "$BEGIN_MARKER" "$WORKFLOW_FILE" || ! grep -qF "$END_MARKER" "$WORKFLOW_FILE"; then
  echo "::error::BEGIN/END kernel_version markers not found in $WORKFLOW_FILE - was the file restructured?" >&2
  exit 1
fi

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

awk -v new_block="$new_block" '
  BEGIN { in_block = 0 }
  index($0, "# BEGIN kernel_version") { print new_block; in_block = 1; next }
  index($0, "# END kernel_version")   { in_block = 0; next }
  in_block { next }
  { print }
' "$WORKFLOW_FILE" > "$tmp_file"

if diff -q "$WORKFLOW_FILE" "$tmp_file" > /dev/null; then
  echo "kernel_version block already up to date (LTS: ${lts_versions[0]}, ${lts_versions[1]}; stable: $current_stable)"
  echo "changed=false" >> "${GITHUB_OUTPUT:-/dev/null}"
else
  mv "$tmp_file" "$WORKFLOW_FILE"
  trap - EXIT
  echo "updated kernel_version block (LTS: ${lts_versions[0]}, ${lts_versions[1]}; stable: $current_stable)"
  echo "changed=true" >> "${GITHUB_OUTPUT:-/dev/null}"
fi
