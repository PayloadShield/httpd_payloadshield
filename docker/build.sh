#!/usr/bin/env bash
# Builds, tests and smoke-tests one image per version in HTTPD_VERSIONS.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSIONS="${HTTPD_VERSIONS:-$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' docker/httpd-versions.json | tr '\n' ' ')}"
if [[ -z "${VERSIONS//[[:space:]]/}" ]]; then
  echo "Error: No Apache httpd versions found in docker/httpd-versions.json" >&2
  exit 1
fi

for version in $VERSIONS; do
  echo "=== Apache httpd $version ==="
  docker build -f docker/Dockerfile \
    --build-arg "HTTPD_VERSION=$version" \
    --target test \
    -t "payloadshield-httpd:$version-test" .
  docker build -f docker/Dockerfile \
    --build-arg "HTTPD_VERSION=$version" \
    --target final \
    -t "payloadshield-httpd:$version" .
  bash docker/smoke_test.sh "payloadshield-httpd:$version" "$version"
done
