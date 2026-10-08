#!/usr/bin/env bash
# Usage: docker/smoke_test.sh IMAGE EXPECTED_HTTPD_VERSION
set -euo pipefail

image="$1"
version="$2"
name="ps-httpd-smoke-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

docker run --rm "$image" httpd -t
docker run --rm "$image" httpd -v 2>&1 | grep -q "Apache/$version"
docker run --rm "$image" httpd -M 2>&1 | grep -q 'payloadshield_module'

docker run -d --name "$name" -p 127.0.0.1::8080 "$image" >/dev/null
port="$(docker port "$name" 8080/tcp | head -n1 | sed 's/.*://')"
for _ in $(seq 1 20); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")" == "200" ]]; then
    echo "smoke OK: $image"
    exit 0
  fi
  sleep 0.5
done

docker logs "$name"
echo "Apache httpd did not serve requests" >&2
exit 1
