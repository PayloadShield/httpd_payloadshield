# httpd_payloadshield
`mod_payloadshield` is an Apache HTTP Server 2.4 module that decrypts the PayloadShield request envelope before the request reaches the application (or `mod_proxy` upstream) and encrypts the response body before it is returned. It is the Apache counterpart of `ngx_payloadshield` and shares its crypto providers and wire format.

## Wire format

Identical to ngx_payloadshield and ComPyPS/ComPHPPS:

* Body is JSON `{"encrypted":"<Base64>"}` in both directions.
* `aes-gcm-256` / `chacha20-poly1305`: Base64 of `12-byte nonce || ciphertext || 16-byte tag`, shared 32-byte key.
* `rsa-hybrid`: Base64 of a JSON object with Base64 `key` (RSA-OAEP-SHA256 wrapped AES key), `nonce` and `data`.

The algorithm is static server configuration; it is never taken from the request.

## Build

Requires Apache 2.4 development files (`apxs`) and OpenSSL 1.1.1+ headers.

```sh
make                # builds mod_payloadshield.la with apxs
sudo make install   # installs mod_payloadshield.so
make test           # crypto unit tests (no Apache needed)
```

## Docker installation

Install Docker Engine or Docker Desktop and make sure the Docker daemon is running. The Docker image builds the Apache module, loads it in Apache, and listens on container port `8080`. PayloadShield processing is disabled until you add directives for the endpoint you want to protect.

Build and start an image locally (replace the version with one from `docker/httpd-versions.json`):

```sh
VERSION=2.4.69
docker build -f docker/Dockerfile --build-arg HTTPD_VERSION="$VERSION" --target final \
  -t "payloadshield-httpd:$VERSION" .
docker run -d --name payloadshield-httpd --restart unless-stopped \
  -p 8080:8080 "payloadshield-httpd:$VERSION"
```

Check that Apache is serving requests:

```sh
curl http://localhost:8080/
```

To enable encryption for an endpoint, copy the image's Apache configuration and add a `<Location>` block. Keep the existing `LoadModule payloadshield_module` line in the copied configuration:

```sh
docker run --rm "payloadshield-httpd:$VERSION" \
  cat /usr/local/apache2/conf/httpd.conf > httpd.conf
```

Add this block to `httpd.conf` and provide a 32-byte symmetric key in `server.key` (or its Base64 encoding):

```apache
<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm aes-gcm-256
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

Do not commit the key to source control. Validate the configuration, then start the container with the configuration and key mounted read-only:

```sh
docker run --rm \
  -v "$PWD/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  -v "$PWD/server.key:/etc/payloadshield/server.key:ro" \
  "payloadshield-httpd:$VERSION" httpd -t

docker rm -f payloadshield-httpd
docker run -d --name payloadshield-httpd --restart unless-stopped \
  -p 8080:8080 \
  -v "$PWD/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  -v "$PWD/server.key:/etc/payloadshield/server.key:ro" \
  "payloadshield-httpd:$VERSION"
```

For a different algorithm, select `chacha20-poly1305` with its 32-byte key, or configure the role-specific PEM files for `rsa-hybrid` as described under [Configuration](#configuration). Use TLS in front of the container; payload encryption does not replace transport security.

To build all listed versions, run the crypto unit tests, and smoke-test the images, use `bash docker/build.sh`. The deployment scripts (`./deploy.sh` on Linux/macOS or `deploy.bat` on Windows) start a container for each listed version on consecutive host ports beginning at `HOST_PORT` (default `8080`). They pull tags from `IMAGE_REPOSITORY` (default `kanduganesh/payloadshield-httpd`); if a tag is missing, they build it and push it to that registry. Set `IMAGE_REPOSITORY`, `CONTAINER_NAME`, and `HOST_PORT` as needed before deployment.

## Configuration

```apache
LoadModule payloadshield_module modules/mod_payloadshield.so

<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm aes-gcm-256
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

| Directive | Meaning |
|---|---|
| `PayloadShield On\|Off` | Enable processing. Default `Off`. |
| `PayloadShieldAlgorithm name` | `aes-gcm-256`, `chacha20-poly1305` or `rsa-hybrid`. Required when enabled. |
| `PayloadShieldKey file` | Symmetric key file: 32 raw bytes or Base64 of 32 bytes. |
| `PayloadShieldPrivateKey file` | RSA private PEM used to decrypt requests (`rsa-hybrid`). |
| `PayloadShieldPublicKey file` | RSA public PEM used to encrypt responses (`rsa-hybrid`). |
| `PayloadShieldMaxBodySize bytes` | Maximum plaintext request/response size. Default 10 MiB. |
| `PayloadShieldFailOpen On\|Off` | Pass data through unchanged when PayloadShield fails. Default `Off`; can expose plaintext. |

Directives are valid in server, virtual host, directory and location contexts. Unsupported algorithms and unreadable keys fail `apachectl configtest`. Set `LimitRequestBody` high enough for the encrypted JSON request.

## Behaviour

* Requests are fully read and decrypted in the `fixups` phase, so `Content-Length` seen by handlers and `mod_proxy` is the plaintext length. Failures return 400 (bad envelope or authentication failure), 413 (too large) or 500.
* Responses are fully buffered, encrypted and sent as `application/json` with a new `Content-Length`. Upstream responses with a `Content-Encoding` other than `identity` are refused (500) unless fail-open is on.
* Subrequests, internal redirects, HEAD, 1xx, 204 and 304 responses are not processed.

This module is a prototype. Compile and integration-test it against the exact httpd/OpenSSL build used in deployment, and combine it with TLS, replay protection and restrictive key-file permissions.
