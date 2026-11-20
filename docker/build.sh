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
  module_file="dist/$version/mod_payloadshield.so"
  if [ ! -f "$module_file" ]; then
    mkdir -p "$(dirname "$module_file")"
    container_id=$(docker create "payloadshield-httpd:$version")
    if ! docker cp "$container_id:/usr/local/apache2/modules/mod_payloadshield.so" "$module_file"; then
      docker rm "$container_id" >/dev/null
      echo "Failed to copy the PayloadShield module for Apache httpd $version" >&2
      exit 1
    fi
    docker rm "$container_id" >/dev/null
  fi
  bash docker/smoke_test.sh "payloadshield-httpd:$version" "$version"
done
